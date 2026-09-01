#!/usr/bin/env python3
"""
test_10_hallucinated_deps.py - Bravo6 Hallucinated Dependency Scanner (v1.0)
==========================================================================
WHAT MAKES THIS SCOUT DIFFERENT

Every other Bravo6 scout tests a general web-security-posture signal that any
site could trigger regardless of how it was built. This one is the exception,
and it is the scout most directly tied to this project's opening argument: it
looks for a declared dependency whose package name does not actually exist on
the ecosystem's public registry.

LLM code assistants sometimes emit an `import` / `require` / a `package.json`
entry for a package that was never published -- a well-documented 2024-2025
phenomenon ("package hallucination", or "slopsquatting" when weaponised). The
exploit path is short and real: an attacker registers the hallucinated name on
the real public registry, publishes malicious code under it, and waits for a
project (human- or AI-assisted) to `npm install` / `pip install` it verbatim.
A confirmed-nonexistent dependency in a reachable manifest is therefore a
concrete, direct supply-chain exposure -- not a hardening nicety -- so every
finding here is tagged raw_data["tier"] = "baseline".

SCOPE (v1) -- WHAT THIS SCOUT CAN AND CANNOT SEE

Bravo6 scans a live, deployed site from the outside with no source-code
access. This scout therefore cannot read a project's real manifest unless the
manifest is *itself* exposed on the public web server (a build artifact left
in a served directory, a misconfigured static file server, ...). v1 is scoped
to exactly that exposure path:

  1. GET a small set of well-known manifest paths at the site root
     (/package.json, /requirements.txt, /Pipfile.lock, /package-lock.json,
     /npm-shrinkwrap.json), reusing test_06_info_disclosure.fetch_path
     rather than reimplementing path probing.
  2. Only if one of them actually comes back and parses as a real manifest,
     extract the declared package names and cross-check each against the
     relevant public registry (registry.npmjs.org / pypi.org).

FUTURE EXTENSION (deliberately NOT built here): inferring dependency names
from unminified same-origin bundled JavaScript (parsing `import`/`require`
statements out of served .js). That meaningfully raises false-positive risk
and scope and is left for a later version.

THE THREE-STATE REGISTRY LOOKUP (see _lookup_package + RegistryResult)

A registry lookup has exactly three outcomes and they must never be collapsed:

  * PRESENT      - the registry returned real package metadata.
  * ABSENT       - the registry returned a clean HTTP 404 for that exact
                   name. This is the ONLY state that produces a
                   hallucinated-dependency finding.
  * INCONCLUSIVE - the lookup itself failed: timeout, rate-limit, 5xx, DNS
                   failure on the registry host, a non-200/404 status, or a
                   malformed body. "We don't know" -- never "confirmed absent".

This is modelled as an explicit enum from the start, not a bare boolean,
specifically because misreading a failed network probe as a confirmed-negative
is a bug this project has already hit twice in test_04_ssl_tls.py (most
recently the rp5.ru false positive, where a fast subprocess-spawn failure was
marked completed=True instead of "unknown"). _lookup_package returns ABSENT
from exactly one place in the function: the branch that sees an HTTP 404
status on a completed response. Every exception handler in it -- and every
other status -- returns INCONCLUSIVE.
"""

import asyncio
import json
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp

# Reuse test_06's path-probing helpers rather than reimplementing them.
# fetch_path(ctx, path, requests_made) -> (status, body); make_url joins safely.
from test_06_info_disclosure import fetch_path as _fetch_path, make_url as _make_url

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
# Fallbacks; the live values are pulled from main_scanner.DEFAULT_TIMEOUTS at
# run() time (see _load_step_timeouts) so the orchestrator stays the single
# source of truth. Two *separate* per-hop budgets: the manifest GET goes to the
# target site, the registry lookups go to a different host (npm/PyPI) with its
# own latency and failure modes -- a slow registry must not block or corrupt
# the target-site portion of the scan.
_DEFAULT_MANIFEST_FETCH_S = 8
_DEFAULT_REGISTRY_LOOKUP_S = 6

MAX_PACKAGES = 60          # cap registry lookups per scan (lock files can be huge)
REGISTRY_CONCURRENCY = 10  # parallel registry lookups


class RegistryResult(Enum):
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    INCONCLUSIVE = "INCONCLUSIVE"


# ------------------------------------------------------------------------------
# Name normalisation
# ------------------------------------------------------------------------------
def _normalize_npm(name: str) -> str:
    # Modern npm names are lowercase; lowercasing here avoids a false 404 on a
    # mis-cased legacy name whose canonical form does exist.
    return (name or "").strip().lower()


def _normalize_pypi(name: str) -> str:
    # PEP 503: collapse runs of [-_.] to a single '-' and lowercase.
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _dedup(pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Dedup (declared, normalized) pairs by normalized name; keep the first
    declared spelling; return sorted by normalized name for determinism."""
    seen: Dict[str, str] = {}
    for declared, norm in pairs:
        if norm and norm not in seen:
            seen[norm] = declared
    return [(seen[n], n) for n in sorted(seen)]


# ------------------------------------------------------------------------------
# Manifest parsers.  Contract:
#   return None       -> not a usable manifest (unparseable / wrong shape / soft-404)
#   return [] or [..] -> usable manifest; list of (declared, normalized) pairs
# ------------------------------------------------------------------------------
def _loads_json(text: str) -> Any:
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


_NPM_MANIFEST_KEYS = ("name", "version", "dependencies", "devDependencies",
                      "optionalDependencies", "peerDependencies", "private",
                      "scripts", "engines")
_NPM_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies",
                     "peerDependencies")


def _parse_package_json(text: str) -> Optional[List[Tuple[str, str]]]:
    data = _loads_json(text)
    if not isinstance(data, dict) or not any(k in data for k in _NPM_MANIFEST_KEYS):
        return None
    pairs: List[Tuple[str, str]] = []
    for section in _NPM_DEP_SECTIONS:
        sec = data.get(section)
        if isinstance(sec, dict):
            for pkg in sec:
                if isinstance(pkg, str) and pkg.strip():
                    pairs.append((pkg.strip(), _normalize_npm(pkg)))
    return _dedup(pairs)


def _walk_lockfile_v1_deps(deps: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for name, meta in deps.items():
        if isinstance(name, str) and name.strip():
            out.append((name.strip(), _normalize_npm(name)))
        if isinstance(meta, dict) and isinstance(meta.get("dependencies"), dict):
            out.extend(_walk_lockfile_v1_deps(meta["dependencies"]))
    return out


def _parse_package_lock(text: str) -> Optional[List[Tuple[str, str]]]:
    data = _loads_json(text)
    if not isinstance(data, dict) or not any(
        k in data for k in ("lockfileVersion", "packages", "dependencies", "name")
    ):
        return None
    pairs: List[Tuple[str, str]] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        marker = "node_modules/"
        for key, meta in packages.items():
            if key:  # "" is the root project itself
                idx = key.rfind(marker)
                name = key[idx + len(marker):] if idx != -1 else key
                name = name.strip("/").strip()
                if name:
                    pairs.append((name, _normalize_npm(name)))
            if isinstance(meta, dict) and isinstance(meta.get("name"), str) and meta["name"].strip():
                pairs.append((meta["name"].strip(), _normalize_npm(meta["name"])))

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        pairs.extend(_walk_lockfile_v1_deps(deps))

    return _dedup(pairs)


def _parse_pipfile_lock(text: str) -> Optional[List[Tuple[str, str]]]:
    data = _loads_json(text)
    if not isinstance(data, dict) or not any(k in data for k in ("_meta", "default", "develop")):
        return None
    pairs: List[Tuple[str, str]] = []
    for section in ("default", "develop"):
        sec = data.get(section)
        if isinstance(sec, dict):
            for pkg in sec:
                if isinstance(pkg, str) and pkg.strip():
                    pairs.append((pkg.strip(), _normalize_pypi(pkg)))
    return _dedup(pairs)


def _parse_requirements_txt(text: str) -> Optional[List[Tuple[str, str]]]:
    if text is None:
        return None
    s = text.strip()
    if not s or s[0] in "{[<":  # JSON object/array, or HTML -> not a requirements file
        return None
    head = s[:300].lower()
    if "<!doctype" in head or "<html" in head or "<head" in head:
        return None

    pairs: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()          # inline comment
        if not line or line.startswith("-"):                            # -e / -r / --hash / -c
            continue
        low = line.lower()
        if low.startswith(("git+", "http://", "https://", "file:", "svn+", "hg+", "bzr+")):
            continue
        if line[0] in "./":                                             # local path install
            continue
        if re.search(r"@\s*(?:https?://|git\+|file:)", line):           # PEP 508 direct URL ref
            continue
        line = line.split(";", 1)[0].strip()                            # environment marker
        line = re.sub(r"\[[^\]]*\]", "", line)                          # extras: pkg[extra]
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not m:
            continue
        pairs.append((m.group(1), _normalize_pypi(m.group(1))))

    # A requirements.txt that yielded zero installable names (only -r/-e/URLs/
    # comments, or genuinely empty) is not a usable manifest for our purpose.
    return _dedup(pairs) if pairs else None


# (path, ecosystem, display-name, parser).  Tried in this order; the FIRST path
# that returns a usable manifest wins and the rest are not fetched.  package.json
# is first: it lists *direct* deps -- exactly what a human or an LLM writes by
# hand -- which is where hallucinated names actually originate.
MANIFEST_SPECS = [
    ("/package.json",        "npm",  "package.json",        _parse_package_json),
    ("/requirements.txt",    "pypi", "requirements.txt",    _parse_requirements_txt),
    ("/Pipfile.lock",        "pypi", "Pipfile.lock",        _parse_pipfile_lock),
    ("/package-lock.json",   "npm",  "package-lock.json",   _parse_package_lock),
    ("/npm-shrinkwrap.json", "npm",  "npm-shrinkwrap.json", _parse_package_lock),
]


# ------------------------------------------------------------------------------
# Registry lookup -- the one function that must never fabricate an ABSENT
# ------------------------------------------------------------------------------
def _registry_url(ecosystem: str, normalized_name: str) -> str:
    if ecosystem == "npm":
        return f"https://registry.npmjs.org/{quote(normalized_name, safe='')}"
    return f"https://pypi.org/pypi/{quote(normalized_name, safe='')}/json"


def _looks_like_real_metadata(ecosystem: str, data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if ecosystem == "npm":
        if data.get("error"):
            return False
        return bool(data.get("name") or data.get("versions") or data.get("dist-tags"))
    # pypi
    if data.get("message") and not data.get("info"):
        return False
    return bool(data.get("info") or data.get("releases") or data.get("urls"))


async def _lookup_package(
    session: Any, ecosystem: str, normalized_name: str, timeout_s: float
) -> Tuple[RegistryResult, str]:
    """Look one package name up on its public registry.

    Returns (RegistryResult, human-readable detail).

    ABSENT is returned from EXACTLY ONE place: the `status == 404` branch on a
    response that actually completed. A 200 with a non-metadata body, any other
    status (3xx/4xx/5xx/429), a timeout, a DNS/connection error, or any other
    exception all return INCONCLUSIVE. There is no code path from an exception
    handler to ABSENT.
    """
    lookup_url = _registry_url(ecosystem, normalized_name)
    timeout = aiohttp.ClientTimeout(total=timeout_s)
    try:
        async with session.get(lookup_url, timeout=timeout, allow_redirects=True) as resp:
            status = resp.status
            if status == 404:
                return RegistryResult.ABSENT, (
                    f"{lookup_url} -> HTTP 404: the registry has no package by this exact name"
                )
            if status != 200:
                return RegistryResult.INCONCLUSIVE, (
                    f"{lookup_url} -> HTTP {status} (expected 200 or 404); treated as 'unknown', not 'absent'"
                )
            try:
                data = await resp.json(content_type=None)
            except Exception:
                return RegistryResult.INCONCLUSIVE, (
                    f"{lookup_url} -> HTTP 200 but the response body did not parse as JSON"
                )
            if _looks_like_real_metadata(ecosystem, data):
                return RegistryResult.PRESENT, f"{lookup_url} -> HTTP 200 with valid package metadata"
            return RegistryResult.INCONCLUSIVE, (
                f"{lookup_url} -> HTTP 200 but the body lacked the expected package-metadata fields"
            )
    except asyncio.TimeoutError:
        return RegistryResult.INCONCLUSIVE, f"{lookup_url} -> request timed out after {timeout_s}s"
    except aiohttp.ClientError as e:
        return RegistryResult.INCONCLUSIVE, f"{lookup_url} -> network error: {type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001 - deliberately conservative: unknown != absent
        return RegistryResult.INCONCLUSIVE, f"{lookup_url} -> unexpected error: {type(e).__name__}: {e}"


# ------------------------------------------------------------------------------
# Finding factory (same convention as test_05/test_07/test_08:
# explicit `tier` param nested under raw_data).
# ------------------------------------------------------------------------------
def _make_finding(title: str, severity: str, confidence: str, cwe: str, owasp: str,
                  location: str, evidence: str, poc: str, remediation: str,
                  detection_method: str, tier: str) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "location": location,
        "evidence": evidence,
        "poc": poc,
        "remediation": remediation,
        "detection_method": detection_method,
        "raw_data": {"tier": tier},
    }


def _no_manifest_finding(url: str, tried_paths: List[str]) -> Dict[str, Any]:
    shown = ", ".join(tried_paths)
    return _make_finding(
        title="No exposed dependency manifest found",
        severity="info",
        confidence="informational",
        cwe="", owasp="",
        location=url,
        evidence=(
            f"None of the well-known dependency-manifest paths ({shown}) returned a parseable "
            f"manifest from {url}. This is the expected, secure-by-default result: the site is "
            "not publicly serving its package.json / requirements.txt / lock files, so their "
            "declared package names cannot be cross-checked against public registries from "
            "outside. This scout has no source-code access -- it can only inspect a manifest "
            "that is itself exposed on the web server."
        ),
        poc="; ".join(f"curl -sI {_make_url(url, p)}" for p in tried_paths[:3]),
        remediation=(
            "No action required. Keep build manifests and lock files out of the web root and "
            "any static-served directory."
        ),
        detection_method="Exposed manifest probe",
        tier="baseline",
    )


def _hallucinated_finding(declared: str, norm: str, detail: str, manifest_display: str,
                          manifest_url: str, ecosystem: str) -> Dict[str, Any]:
    registry_short = "npm" if ecosystem == "npm" else "PyPI"
    name_note = "" if declared == norm else f" (normalised to '{norm}' for the lookup)"
    install_cmd = f"npm install {declared}" if ecosystem == "npm" else f"pip install {declared}"
    publish_cmd = "npm publish" if ecosystem == "npm" else "twine upload"
    return _make_finding(
        title=f"Hallucinated dependency: '{declared}' is not published on {registry_short}",
        severity="critical",
        confidence="verified-live",
        cwe="CWE-829",
        owasp="A08:2021-Software and Data Integrity Failures",
        location=manifest_url,
        evidence=(
            f"The publicly-exposed manifest {manifest_display} ({manifest_url}) declares a "
            f"dependency on '{declared}'{name_note}, but a direct registry lookup confirms the "
            f"package does not exist: {detail}. An unclaimed dependency name in a reachable "
            f"manifest is a live supply-chain exposure -- an attacker can register '{norm}' on "
            f"the public registry, publish malicious code under it, and have it pulled into any "
            f"environment that runs an install against this manifest (package 'hallucination' / "
            f"slopsquatting). A name that resolves to a clean 404 is characteristic of an "
            f"AI-generated import that was never a real package."
        ),
        poc=(
            f"# 1. Confirm the name is unclaimed:\n"
            f"curl -sI {_registry_url(ecosystem, norm)}    # -> HTTP 404\n"
            f"# 2. Attacker claims it:   {publish_cmd}   (package name: {norm})\n"
            f"# 3. Victim pulls it on:   {install_cmd}"
        ),
        remediation=(
            f"Verify '{declared}' is a real, intended package name. If it was introduced by an "
            f"AI coding assistant or a typo, remove it or correct it to the intended package. "
            f"If it is meant to be private/internal, publish it under a private registry (and, "
            f"for npm, a scoped @org/ name) and defensively pre-register the public name as an "
            f"empty placeholder to block takeover. Separately, stop serving {manifest_display} "
            f"as a public static file."
        ),
        detection_method="Exposed manifest + public registry lookup",
        tier="baseline",
    )


def _inconclusive_finding(items: List[Tuple[str, str, str]], manifest_display: str,
                          manifest_url: str, registry_name: str) -> Dict[str, Any]:
    listed = "; ".join(f"'{d}' ({det})" for d, _n, det in items[:12])
    more = "" if len(items) <= 12 else f" (+{len(items) - 12} more)"
    return _make_finding(
        title=f"Dependency verification inconclusive for {len(items)} package(s)",
        severity="info",
        confidence="plausible-unconfirmed",
        cwe="", owasp="",
        location=manifest_url,
        evidence=(
            f"These packages from {manifest_display} could not be checked against "
            f"{registry_name} because the registry lookup itself did not complete cleanly "
            f"(timeout, rate-limit, 5xx, a non-200/404 status, or a malformed response): "
            f"{listed}{more}. This is explicitly NOT a 'confirmed absent' result -- these "
            f"packages are neither confirmed-present nor confirmed-hallucinated, and none of "
            f"them are counted toward the hallucinated-dependency total. Only a clean registry "
            f"404 produces a hallucinated-dependency finding."
        ),
        poc=(
            "Re-run the scan when the registry is reachable, or check manually: "
            "curl -sI https://registry.npmjs.org/<name>  |  curl -sI https://pypi.org/pypi/<name>/json"
        ),
        remediation=(
            "Re-run this check when the public registry is reachable from the scanner. If "
            "lookups fail consistently, verify the scanner's outbound path to "
            "registry.npmjs.org / pypi.org (egress proxy, firewall, or rate-limiting)."
        ),
        detection_method="Exposed manifest + public registry lookup (inconclusive)",
        tier="baseline",
    )


# ------------------------------------------------------------------------------
# Timeout wiring
# ------------------------------------------------------------------------------
def _load_step_timeouts(ctx: Any) -> Tuple[float, float]:
    """Prefer main_scanner.DEFAULT_TIMEOUTS as the single source of truth for
    the two per-hop budgets; fall back to local defaults if it can't be
    imported. Done lazily (inside run()) so plugin discovery can never hit an
    import cycle."""
    manifest_s, registry_s = _DEFAULT_MANIFEST_FETCH_S, _DEFAULT_REGISTRY_LOOKUP_S
    try:
        from main_scanner import DEFAULT_TIMEOUTS
        manifest_s = DEFAULT_TIMEOUTS.get("test_10_hallucinated_deps_manifest_fetch", manifest_s)
        registry_s = DEFAULT_TIMEOUTS.get("test_10_hallucinated_deps_registry_lookup", registry_s)
    except Exception:
        pass
    cfg = getattr(ctx, "config", None) or {}
    manifest_s = cfg.get("hallucinated_deps_manifest_timeout", manifest_s)
    registry_s = cfg.get("hallucinated_deps_registry_timeout", registry_s)
    return manifest_s, registry_s


async def _get_manifest(ctx: Any, path: str, requests_made: List[int], timeout_s: float) -> Tuple[int, str]:
    """Fetch one manifest path via test_06's fetch_path, wrapped in our own
    (short) per-request budget on top of fetch_path's internal timeout."""
    try:
        return await asyncio.wait_for(_fetch_path(ctx, path, requests_made), timeout=timeout_s)
    except Exception:
        return 0, ""


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
async def run(ctx: Any) -> dict:
    """Entry point for the Hallucinated Dependency scout.

    Uses only: ctx.url, ctx.session, ctx.page_is_representative, ctx.config.
    """
    if not getattr(ctx, "page_is_representative", True):
        return {"fatal_error": "Page is not representative (e.g., WAF block or hard error); skipping hallucinated-dependency scan."}

    url = getattr(ctx, "url", "https://example.com")
    manifest_fetch_s, registry_lookup_s = _load_step_timeouts(ctx)

    manifest_requests = [0]
    tried_paths: List[str] = []
    found: Optional[Tuple[str, str, str, List[Tuple[str, str]]]] = None

    for path, ecosystem, display, parser in MANIFEST_SPECS:
        tried_paths.append(path)
        status, body = await _get_manifest(ctx, path, manifest_requests, manifest_fetch_s)
        if status != 200 or not body:
            continue
        parsed = parser(body)
        if parsed is None:  # present at the URL but not a usable manifest -> keep looking
            continue
        found = (path, ecosystem, display, parsed)
        break

    if found is None:
        return {
            "findings": [_no_manifest_finding(url, tried_paths)],
            "details": {
                "requests_made": manifest_requests[0],
                "registry_lookups_made": 0,
                "manifest_found": None,
                "paths_probed": tried_paths,
            },
        }

    path, ecosystem, display, all_pairs = found
    manifest_url = _make_url(url, path)
    registry_name = "npm (registry.npmjs.org)" if ecosystem == "npm" else "PyPI (pypi.org)"

    # Skip scoped/private-style npm names: '@org/pkg' legitimately 404s on the
    # public registry when it's a private package, so flagging it would be a
    # structural false positive, not an edge case.
    scoped_skipped: List[str] = []
    checkable: List[Tuple[str, str]] = []
    for declared, norm in all_pairs:
        if ecosystem == "npm" and declared.startswith("@"):
            scoped_skipped.append(declared)
        else:
            checkable.append((declared, norm))

    not_checked_cap = 0
    if len(checkable) > MAX_PACKAGES:
        not_checked_cap = len(checkable) - MAX_PACKAGES
        checkable = checkable[:MAX_PACKAGES]  # deterministic: already sorted by normalized name

    sem = asyncio.Semaphore(REGISTRY_CONCURRENCY)

    async def _check(declared: str, norm: str):
        async with sem:
            result, detail = await _lookup_package(ctx.session, ecosystem, norm, registry_lookup_s)
            return declared, norm, result, detail

    lookups = await asyncio.gather(*[_check(d, n) for d, n in checkable]) if checkable else []

    absent = [(d, n, det) for (d, n, r, det) in lookups if r is RegistryResult.ABSENT]
    inconclusive = [(d, n, det) for (d, n, r, det) in lookups if r is RegistryResult.INCONCLUSIVE]
    present_count = sum(1 for (_d, _n, r, _det) in lookups if r is RegistryResult.PRESENT)

    findings: List[Dict[str, Any]] = []
    for declared, norm, detail in absent:
        findings.append(_hallucinated_finding(declared, norm, detail, display, manifest_url, ecosystem))
    if inconclusive:
        findings.append(_inconclusive_finding(inconclusive, display, manifest_url, registry_name))

    return {
        "findings": findings,
        "details": {
            "requests_made": manifest_requests[0],           # target-facing GETs only
            "registry_lookups_made": len(lookups),
            "manifest_found": path,
            "ecosystem": ecosystem,
            "packages_declared": len(all_pairs),
            "packages_checked": len(lookups),
            "packages_skipped_scoped": scoped_skipped,
            "packages_not_checked_due_to_cap": not_checked_cap,
            "result_counts": {
                "PRESENT": present_count,
                "ABSENT": len(absent),
                "INCONCLUSIVE": len(inconclusive),
            },
        },
    }


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 Hallucinated Dependency Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest

        _NO_JSON = object()

        class _FakeContent:
            def __init__(self, data: bytes):
                self._data = data

            async def read(self, n: int = -1) -> bytes:
                return self._data

        class _FakeResp:
            def __init__(self, status: int = 200, body: str = "", json_data: Any = _NO_JSON):
                self.status = status
                self._body = body
                self._json = json_data
                self.url = "http://fake.test/"

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            @property
            def content(self):
                b = self._body.encode() if isinstance(self._body, str) else self._body
                return _FakeContent(b)

            async def text(self):
                return self._body

            async def json(self, content_type=None, **kw):
                if self._json is _NO_JSON:
                    raise ValueError("no json body")
                return self._json

        class _RaiseCM:
            def __init__(self, exc: BaseException):
                self._exc = exc

            async def __aenter__(self):
                raise self._exc

            async def __aexit__(self, *a):
                return False

        class _FakeSession:
            """Routes session.get(url) by substring. A route value that is an
            exception instance makes the `async with` raise it."""
            def __init__(self, routes=None, default_status: int = 404):
                self._routes = routes or []
                self._default_status = default_status
                self.calls: List[str] = []

            def get(self, url, **kw):
                self.calls.append(url)
                for substr, resp in self._routes:
                    if substr in url:
                        if isinstance(resp, BaseException):
                            return _RaiseCM(resp)
                        return resp
                return _FakeResp(self._default_status)

        class _Ctx:
            def __init__(self, session, url="https://example.com", page_is_representative=True):
                self.session = session
                self.url = url
                self.page_is_representative = page_is_representative
                self.config = {}

        def _run(session, **kw):
            return asyncio.run(run(_Ctx(session, **kw)))

        PKG_JSON = '{"name":"demo","version":"1.0.0","dependencies":{%s}}'

        # ---- Parser unit tests -------------------------------------------------
        class TestParsers(unittest.TestCase):
            def test_package_json_extracts_all_dep_sections(self):
                text = ('{"name":"x","version":"1","dependencies":{"lodash":"^4"},'
                        '"devDependencies":{"jest":"^29"},"peerDependencies":{"react":"^18"}}')
                names = [n for _d, n in _parse_package_json(text)]
                self.assertEqual(names, ["jest", "lodash", "react"])

            def test_package_json_manifest_shaped_but_no_deps_is_empty_list_not_none(self):
                self.assertEqual(_parse_package_json('{"name":"x","version":"1.0.0"}'), [])

            def test_non_manifest_json_is_none(self):
                self.assertIsNone(_parse_package_json('{"foo":"bar","baz":1}'))

            def test_unparseable_is_none(self):
                self.assertIsNone(_parse_package_json("<html>not json</html>"))
                self.assertIsNone(_parse_package_json(""))

            def test_requirements_txt_skips_non_registry_lines(self):
                text = (
                    "# a comment\n"
                    "requests==2.31.0\n"
                    "Flask>=2.0  # inline comment\n"
                    "-e .\n"
                    "-r other.txt\n"
                    "git+https://github.com/foo/bar.git\n"
                    "https://example.com/pkg.tar.gz\n"
                    "./local/path\n"
                    "internal-pkg @ https://example.com/internal.whl\n"
                    "requests-toolbelt[security]; python_version < '3.8'\n"
                )
                names = [n for _d, n in _parse_requirements_txt(text)]
                self.assertEqual(names, ["flask", "requests", "requests-toolbelt"])

            def test_requirements_txt_json_body_is_none(self):
                self.assertIsNone(_parse_requirements_txt('{"dependencies":{}}'))

            def test_requirements_txt_only_directives_is_none(self):
                self.assertIsNone(_parse_requirements_txt("# nothing\n-r base.txt\n"))

            def test_package_lock_v3_packages_map(self):
                text = json.dumps({
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "root"},
                        "node_modules/lodash": {"version": "4.17.21"},
                        "node_modules/@types/node": {"version": "20.0.0"},
                        "node_modules/a/node_modules/b": {"version": "1.0.0"},
                    },
                })
                names = [n for _d, n in _parse_package_lock(text)]
                self.assertIn("lodash", names)
                self.assertIn("b", names)
                self.assertIn("@types/node", names)

            def test_package_lock_v1_nested_dependencies(self):
                text = json.dumps({
                    "lockfileVersion": 1,
                    "dependencies": {
                        "lodash": {"version": "4.17.21"},
                        "chalk": {"version": "5.0.0", "dependencies": {"ansi-styles": {"version": "6.0.0"}}},
                    },
                })
                names = [n for _d, n in _parse_package_lock(text)]
                self.assertEqual(names, ["ansi-styles", "chalk", "lodash"])

            def test_pipfile_lock(self):
                text = json.dumps({
                    "_meta": {"hash": {}},
                    "default": {"requests": {"version": "==2.31.0"}},
                    "develop": {"pytest": {"version": "==7.0.0"}},
                })
                names = [n for _d, n in _parse_pipfile_lock(text)]
                self.assertEqual(names, ["pytest", "requests"])

        # ---- _lookup_package: the ABSENT-only-from-404 guarantee -------------
        class TestLookupThreeState(unittest.TestCase):
            def _lookup(self, resp, ecosystem="npm"):
                sess = _FakeSession(routes=[("registry.npmjs.org", resp), ("pypi.org", resp)])
                return asyncio.run(_lookup_package(sess, ecosystem, "somepkg", 3))

            def test_clean_404_is_the_only_path_to_absent(self):
                result, _ = self._lookup(_FakeResp(404, body='{"error":"Not found"}'))
                self.assertIs(result, RegistryResult.ABSENT)

            def test_200_with_metadata_is_present(self):
                result, _ = self._lookup(_FakeResp(200, json_data={"name": "somepkg", "versions": {}}))
                self.assertIs(result, RegistryResult.PRESENT)

            def test_200_error_body_is_inconclusive_not_absent(self):
                result, _ = self._lookup(_FakeResp(200, json_data={"error": "Not found"}))
                self.assertIs(result, RegistryResult.INCONCLUSIVE)

            def test_200_non_json_is_inconclusive_not_absent(self):
                result, _ = self._lookup(_FakeResp(200, body="<html>rate limited</html>"))
                self.assertIs(result, RegistryResult.INCONCLUSIVE)

            def test_various_non_404_statuses_are_inconclusive_never_absent(self):
                for status in (301, 401, 403, 429, 500, 502, 503):
                    result, _ = self._lookup(_FakeResp(status, body="x"))
                    self.assertIs(result, RegistryResult.INCONCLUSIVE, f"status {status}")
                    self.assertIsNot(result, RegistryResult.ABSENT, f"status {status}")

            def test_timeout_is_inconclusive_never_absent(self):
                result, _ = self._lookup(asyncio.TimeoutError())
                self.assertIs(result, RegistryResult.INCONCLUSIVE)
                self.assertIsNot(result, RegistryResult.ABSENT)

            def test_client_error_is_inconclusive_never_absent(self):
                result, _ = self._lookup(aiohttp.ClientConnectionError("dns boom"))
                self.assertIs(result, RegistryResult.INCONCLUSIVE)

            def test_generic_exception_is_inconclusive_never_absent(self):
                result, _ = self._lookup(RuntimeError("something weird"))
                self.assertIs(result, RegistryResult.INCONCLUSIVE)

            def test_pypi_404_is_absent(self):
                result, _ = self._lookup(_FakeResp(404, body='{"message":"Not Found"}'), ecosystem="pypi")
                self.assertIs(result, RegistryResult.ABSENT)

        # ---- End-to-end run() regression tests (task-mandated) --------------
        class TestRunEndToEnd(unittest.TestCase):
            def _titles(self, result):
                return [f["title"] for f in result["findings"]]

            def _severities(self, result):
                return [f["severity"] for f in result["findings"]]

            def test_no_manifest_exposed_emits_info_and_stops(self):
                result = _run(_FakeSession(default_status=404))
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "No exposed dependency manifest found")
                self.assertEqual(f["severity"], "info")
                self.assertEqual(f["raw_data"]["tier"], "baseline")
                self.assertEqual(result["details"]["registry_lookups_made"], 0)

            def test_manifest_with_all_real_packages_produces_no_finding(self):
                sess = _FakeSession(routes=[
                    ("/package.json", _FakeResp(200, PKG_JSON % '"lodash":"^4.17.0","react":"^18.2.0"')),
                    ("registry.npmjs.org/lodash", _FakeResp(200, json_data={"name": "lodash", "versions": {}})),
                    ("registry.npmjs.org/react", _FakeResp(200, json_data={"name": "react", "versions": {}})),
                ])
                result = _run(sess)
                self.assertEqual(result["findings"], [])
                self.assertEqual(result["details"]["result_counts"], {"PRESENT": 2, "ABSENT": 0, "INCONCLUSIVE": 0})

            def test_one_package_genuine_404_is_critical_confirmed_absent(self):
                sess = _FakeSession(
                    routes=[
                        ("/package.json", _FakeResp(200, PKG_JSON % '"lodash":"^4.17.0","totally-not-real-xyz9":"^1.0.0"')),
                        ("registry.npmjs.org/lodash", _FakeResp(200, json_data={"name": "lodash", "versions": {}})),
                        # totally-not-real-xyz9 falls through to default 404
                    ],
                    default_status=404,
                )
                result = _run(sess)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["severity"], "critical")
                self.assertEqual(f["confidence"], "verified-live")
                self.assertEqual(f["raw_data"]["tier"], "baseline")
                self.assertIn("totally-not-real-xyz9", f["title"])
                self.assertIn("totally-not-real-xyz9", f["evidence"])
                self.assertIn("package.json", f["evidence"])
                self.assertIn("HTTP 404", f["evidence"])

            def test_scoped_package_is_skipped_not_checked(self):
                sess = _FakeSession(
                    routes=[
                        ("/package.json", _FakeResp(200, PKG_JSON % '"@acme/secret-internal":"^1.0.0","lodash":"^4.17.0"')),
                        ("registry.npmjs.org/lodash", _FakeResp(200, json_data={"name": "lodash", "versions": {}})),
                    ],
                    default_status=404,
                )
                result = _run(sess)
                self.assertEqual(result["findings"], [], "Scoped name must not produce a finding.")
                self.assertEqual(result["details"]["packages_skipped_scoped"], ["@acme/secret-internal"])
                self.assertFalse(
                    any("acme" in c or "%40acme" in c for c in sess.calls),
                    "Scoped package must never be looked up on the public registry.",
                )

            def test_registry_timeout_is_inconclusive_not_false_critical(self):
                sess = _FakeSession(routes=[
                    ("/package.json", _FakeResp(200, PKG_JSON % '"maybe-real-pkg":"^1.0.0"')),
                    ("registry.npmjs.org/maybe-real-pkg", asyncio.TimeoutError()),
                ])
                result = _run(sess)
                self.assertNotIn("critical", self._severities(result),
                                 "A timed-out lookup must NEVER produce a confirmed-absent critical.")
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertIn("inconclusive", f["title"].lower())
                self.assertEqual(f["confidence"], "plausible-unconfirmed")
                self.assertEqual(f["raw_data"]["tier"], "baseline")
                self.assertEqual(result["details"]["result_counts"]["ABSENT"], 0)
                self.assertEqual(result["details"]["result_counts"]["INCONCLUSIVE"], 1)

            def test_manifest_present_but_unparseable_is_treated_as_no_manifest(self):
                sess = _FakeSession(
                    routes=[("/package.json", _FakeResp(200, "<html><body>404 not found</body></html>"))],
                    default_status=404,
                )
                result = _run(sess)
                self.assertEqual(len(result["findings"]), 1)
                self.assertEqual(result["findings"][0]["title"], "No exposed dependency manifest found")
                self.assertNotIn("critical", self._severities(result))

            def test_absent_and_inconclusive_coexist_and_are_counted_separately(self):
                sess = _FakeSession(
                    routes=[
                        ("/package.json", _FakeResp(200, PKG_JSON % '"real-pkg":"^1","ghost-pkg":"^1","unknown-pkg":"^1"')),
                        ("registry.npmjs.org/real-pkg", _FakeResp(200, json_data={"name": "real-pkg", "versions": {}})),
                        ("registry.npmjs.org/ghost-pkg", _FakeResp(404)),
                        ("registry.npmjs.org/unknown-pkg", _FakeResp(503, body="upstream error")),
                    ],
                )
                result = _run(sess)
                counts = result["details"]["result_counts"]
                self.assertEqual(counts, {"PRESENT": 1, "ABSENT": 1, "INCONCLUSIVE": 1})
                self.assertEqual(len(result["findings"]), 2)
                for f in result["findings"]:
                    self.assertEqual(f["raw_data"]["tier"], "baseline")
                crit = [f for f in result["findings"] if f["severity"] == "critical"]
                self.assertEqual(len(crit), 1)
                self.assertIn("ghost-pkg", crit[0]["title"])

            def test_requirements_txt_pypi_path_end_to_end(self):
                sess = _FakeSession(
                    routes=[
                        ("/requirements.txt", _FakeResp(200, "requests==2.31.0\nnonexistent-pkg-q7==0.1\n")),
                        ("pypi.org/pypi/requests/json", _FakeResp(200, json_data={"info": {"name": "requests"}})),
                        # nonexistent-pkg-q7 -> default 404
                    ],
                    default_status=404,
                )
                result = _run(sess)
                self.assertEqual(result["details"]["ecosystem"], "pypi")
                self.assertEqual(len(result["findings"]), 1)
                self.assertIn("nonexistent-pkg-q7", result["findings"][0]["title"])
                self.assertIn("PyPI", result["findings"][0]["title"])

            def test_non_representative_page_skips_scan(self):
                result = _run(_FakeSession(), page_is_representative=False)
                self.assertIn("fatal_error", result)

            def test_first_usable_manifest_wins_no_further_fetches(self):
                sess = _FakeSession(routes=[
                    ("/package.json", _FakeResp(200, PKG_JSON % '"lodash":"^4"')),
                    ("registry.npmjs.org/lodash", _FakeResp(200, json_data={"name": "lodash"})),
                ])
                _run(sess)
                self.assertFalse(any("requirements.txt" in c for c in sess.calls))
                self.assertFalse(any("package-lock.json" in c for c in sess.calls))

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import aiohttp as _aiohttp
        from dataclasses import dataclass, field

        @dataclass
        class DummyContext:
            url: str
            session: Any = None
            page_is_representative: bool = True
            config: dict = field(default_factory=dict)

        async def _live_scan():
            connector = _aiohttp.TCPConnector(ssl=True)
            async with _aiohttp.ClientSession(
                connector=connector, headers={"User-Agent": "Bravo6-Scanner/8.5"}
            ) as session:
                ctx = DummyContext(url=args.url, session=session)
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())
