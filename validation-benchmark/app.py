from __future__ import annotations

from flask import Flask, make_response, request, Response


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return make_response(
            """
            <html>
              <head>
                <title>Bravo6 Benchmark</title>
                <meta charset="utf-8">
                <meta name="description" content="Secure benchmark landing page">
                <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'">
                <meta http-equiv="Strict-Transport-Security" content="max-age=63072000; includeSubDomains; preload">
                <meta http-equiv="X-Frame-Options" content="DENY">
                <meta http-equiv="X-Content-Type-Options" content="nosniff">
                <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
                <meta http-equiv="Permissions-Policy" content="geolocation=(), camera=()">
              </head>
              <body>
                <h1>Bravo6 Benchmark</h1>
                <p>Secure baseline case.</p>
              </body>
            </html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/secure")
    def secure() -> Response:
        return index()

    @app.get("/secrets-positive")
    def secrets_positive() -> Response:
        content = """
        <html><head><title>Secrets Positive</title></head><body>
        <script>
          const apiKey = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef";
          const openAiKey = "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef";
          const databaseUri = "postgresql://svc_user:supersecretpass@db.example.com:5432/app";
        </script>
        </body></html>
        """
        resp = make_response(content, 200, {"Content-Type": "text/html; charset=utf-8"})
        return resp

    @app.get("/secrets-negative")
    def secrets_negative() -> Response:
        return make_response(
            """
            <html><head><title>Secrets Negative</title></head><body>
            <script>
              const placeholder = "replace_me";
              const demoToken = "example-token-not-real";
            </script>
            </body></html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/libs-positive")
    def libs_positive() -> Response:
        content = """
        <html><head>
          <script src="https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js"></script>
          <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js"></script>
        </head><body><h1>Libraries Positive</h1></body></html>
        """
        return make_response(content, 200, {"Content-Type": "text/html; charset=utf-8"})

    @app.get("/libs-negative")
    def libs_negative() -> Response:
        content = """
        <html><head>
          <script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>
        </head><body><h1>Libraries Negative</h1></body></html>
        """
        return make_response(content, 200, {"Content-Type": "text/html; charset=utf-8"})

    @app.get("/cookies-weak")
    def cookies_weak() -> Response:
        resp = make_response("<html><body>Weak cookie case</body></html>", 200)
        resp.set_cookie("session", "abc123")
        resp.set_cookie("tracker", "xyz987")
        resp.set_cookie("__Host_session", "bad", path="/")
        return resp

    @app.get("/cookies-strong")
    def cookies_strong() -> Response:
        resp = make_response("<html><body>Strong cookie case</body></html>", 200)
        resp.set_cookie("session", "abc123", secure=True, httponly=True, samesite="Lax", path="/")
        return resp

    @app.get("/headers-missing")
    def headers_missing() -> Response:
        return make_response("<html><body>Missing security headers</body></html>", 200)

    @app.get("/headers-safe")
    def headers_safe() -> Response:
        resp = make_response("<html><body>Headers safe</body></html>", 200, {"Content-Type": "text/html; charset=utf-8"})
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return resp

    @app.get("/info-disclosure-positive")
    def info_disclosure_positive() -> Response:
        return make_response("<html><body>Info disclosure positive</body></html>", 200)

    @app.route("/info-disclosure-positive/<path:subpath>", methods=["GET"])
    def info_disclosure_positive_file(subpath: str) -> Response:
        file_map = {
            ".env": "API_KEY=BENCHMARK_OPENAI_PLACEHOLDER\nDB_PASSWORD=benchmark_password\n",
            ".git/config": "[core]\n\trepositoryformatversion = 0\n",
            ".git/HEAD": "ref: refs/heads/main\n",
            ".htpasswd": "admin:$apr1$abc123$Q3v7KJ0f0fA0mR0d0Xn4Q/\n",
            "wp-config.php": "<?php\ndefine('DB_PASSWORD', 'local-db-password-123');\ndefine('DB_USER', 'admin');\ndefine('DB_NAME', 'benchmark');\n?>\n",
            ".svn/entries": "dir\n",
            "phpinfo.php": "<html><title>phpinfo()</title><body>PHP Version 8.2.0</body></html>",
            "config.php": "<?php\n$db_password = 'local-db-password-123';\n?>\n",
            "adminer.php": "<html><title>Login - Adminer</title><form>adminer</form></html>",
            ".vscode/settings.json": '{"settings": {"debug": true}}\n',
            "composer.json": '{"name": "benchmark-site", "require": {"php": ">=8.0"}}\n',
            "package.json": '{"name": "benchmark-site", "dependencies": {"imaginary-not-published-package": "1.0.0", "react": "18.2.0"}}\n',
        }
        if subpath in file_map:
            content_type = "application/json" if subpath.endswith(".json") else "text/plain; charset=utf-8"
            if subpath.endswith(".php") or subpath == "phpinfo.php":
                content_type = "text/html; charset=utf-8"
            return make_response(file_map[subpath], 200, {"Content-Type": content_type})
        return make_response("Not found", 404)

    @app.get("/benchmark-secrets-fixture")
    def benchmark_secrets_fixture() -> Response:
        return make_response(
            "<html><body><script>const benchmarkValue = 'BENCHMARK_PLACEHOLDER_VALUE_001234567890abcdef';</script></body></html>",
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.route("/cors-open", methods=["GET", "OPTIONS"])
    def cors_open() -> Response:
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Methods": "GET, PUT, DELETE",
        }
        if request.method == "OPTIONS":
            return make_response("", 200, headers)
        resp = make_response("<html><body>CORS open</body></html>", 200)
        resp.headers.update(headers)
        return resp

    @app.get("/cors-closed")
    def cors_closed() -> Response:
        return make_response("<html><body>CORS closed</body></html>", 200)

    @app.get("/sri-missing")
    def sri_missing() -> Response:
        return make_response(
            """
            <html><head>
              <script src="https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js"></script>
            </head><body>Missing SRI</body></html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/sri-safe")
    def sri_safe() -> Response:
        return make_response(
            """
            <html><head>
              <script src="https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js" integrity="sha384-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" crossorigin="anonymous"></script>
            </head><body>Safe SRI</body></html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.get("/hallucinated-dep-positive")
    def hallucinated_dep_positive() -> Response:
        return make_response(
            """
            <html><body>Hallucinated dep positive</body></html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    @app.route("/hallucinated-dep-positive/<path:subpath>", methods=["GET"])
    def hallucinated_dep_positive_file(subpath: str) -> Response:
        manifest_map = {
            "package.json": '{"name": "benchmark-site", "dependencies": {"imaginary-not-published-package": "1.0.0", "react": "18.2.0"}}\n',
            "requirements.txt": "imaginary-not-published-package==1.0.0\nrequests==2.32.3\n",
            "Pipfile.lock": '{"_meta": {"hash": {}}, "default": {"imaginary-not-published-package": {"version": "==1.0.0"}}, "develop": {}}\n',
            "package-lock.json": '{"name": "benchmark-site", "lockfileVersion": 3, "packages": {"": {"name": "benchmark-site"}, "node_modules/imaginary-not-published-package": {"version": "1.0.0"}}}\n',
            "npm-shrinkwrap.json": '{"name": "benchmark-site", "lockfileVersion": 3, "packages": {"": {"name": "benchmark-site"}, "node_modules/imaginary-not-published-package": {"version": "1.0.0"}}}\n',
        }
        if subpath in manifest_map:
            content_type = "application/json" if subpath.endswith(".json") else "text/plain; charset=utf-8"
            return make_response(manifest_map[subpath], 200, {"Content-Type": content_type})
        return make_response("Not found", 404)

    @app.get("/hallucinated-dep-negative")
    def hallucinated_dep_negative() -> Response:
        return make_response(
            """
            <html><body>Hallucinated dep negative</body></html>
            """,
            200,
            {"Content-Type": "text/html; charset=utf-8"},
        )

    # Exposed manifest files used by the hallucinated dependency and config disclosure scanners.
    @app.get("/package.json")
    def package_json() -> Response:
        body = {
            "name": "benchmark-site",
            "dependencies": {
                "imaginary-not-published-package": "1.0.0",
                "react": "18.2.0",
            },
        }
        return make_response(__import__("json").dumps(body), 200, {"Content-Type": "application/json"})

    @app.get("/requirements.txt")
    def requirements_txt() -> Response:
        return make_response("requests==2.32.3\nflask==3.0.3\n", 200, {"Content-Type": "text/plain"})

    @app.get("/wp-config.php")
    def wp_config() -> Response:
        content = """
        <?php
        define('DB_PASSWORD', 'local-db-password-123');
        define('DB_USER', 'admin');
        define('DB_NAME', 'benchmark');
        ?>
        """
        return make_response(content, 200, {"Content-Type": "text/plain; charset=utf-8"})

    @app.get("/.env")
    def env_file() -> Response:
        return make_response("API_KEY=BENCHMARK_FAKE_OPENAI_KEY_abcdef\nDB_PASSWORD=benchmark_password\n", 200, {"Content-Type": "text/plain; charset=utf-8"})

    @app.get("/.git/config")
    def git_config() -> Response:
        return make_response("[core]\n\trepositoryformatversion = 0\n", 200, {"Content-Type": "text/plain; charset=utf-8"})

    @app.get("/adminer.php")
    def adminer() -> Response:
        return make_response("<html><title>Login - Adminer</title><form>adminer</form></html>", 200)

    @app.get("/robots.txt")
    def robots() -> Response:
        return make_response("User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain; charset=utf-8"})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5001, debug=False)
