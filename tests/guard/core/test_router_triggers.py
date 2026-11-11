"""Router trigger table: the regex layer must recognise what it claims."""

from __future__ import annotations

from plugins.violin_router.core.triggers import load_triggers, scan_text


def test_every_trigger_declares_patterns_and_skills() -> None:
    triggers = load_triggers()
    assert triggers, "the trigger table must not be empty"
    for name, trigger in triggers.items():
        assert trigger.patterns, f"{name} has no compiled pattern"
        assert trigger.kind in {"vuln", "tech"}, f"{name} has an unknown kind"
        assert trigger.skills, f"{name} routes to no skill"


def test_regex_recognises_known_error_signatures() -> None:
    triggers = load_triggers()
    cases = {
        "SQLSTATE[42000]: Syntax error in query": "sqli",
        "You have an error in your SQL syntax near 'x'": "sqli",
        "ORA-01756: quoted string not properly terminated": "sqli",
        "Request to 169.254.169.254/latest/meta-data/ timed out": "ssrf",
        "http://xyz.interact.sh/ callback received": "ssrf",
        "jinja2.exceptions.TemplateSyntaxError: unexpected '}'": "ssti",
        "com.mysql.jdbc.exceptions.MySQLSyntaxErrorException": "sqli",
        "AKIAIOSFODNN7EXAMPLE in bucket policy": "aws",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig": "jwt",
    }
    for text, expected in cases.items():
        hits = {trigger.name for trigger, _ in scan_text(text, triggers)}
        assert expected in hits, f"{expected!r} not detected in {text!r} (got {sorted(hits)})"


def test_regex_ignores_ordinary_output() -> None:
    triggers = load_triggers()
    noise = [
        "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx",
        "found 12 subdomains in 3.2s",
        "user@example.com logged in successfully",
    ]
    for text in noise:
        hits = scan_text(text, triggers)
        assert not hits, f"unexpected detection in {text!r}: {[t.name for t, _ in hits]}"


def test_scan_returns_the_matched_snippet_for_audit() -> None:
    triggers = load_triggers()
    hits = scan_text("boom SQLSTATE[42000] trailing context", triggers)
    assert hits
    trigger, snippet = hits[0]
    assert trigger.name == "sqli"
    assert "SQLSTATE" in snippet
