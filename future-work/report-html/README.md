# Deferred HTML reporting

`report_generator.py` is a deferred renderer. The active Report Function returns JSON from its status/result routes; this module is not wired into that path.

Restoring HTML output would require integration, escaping/content review, and access-control decisions. Do not infer that templates or generated reports are safe to publish merely because the renderer exists.

[Active report contract](../../docs/api-reference.md)
