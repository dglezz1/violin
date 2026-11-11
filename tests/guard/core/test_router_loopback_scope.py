"""Loopback as a primary target is refused unless the scope opts in."""

from __future__ import annotations

from pathlib import Path

from plugins.violin_guard.core.commands.targets import check_scope_targets

SCOPE_TEMPLATE = """
targets:
  domains: []
  ip_addresses:
  - 127.0.0.1
  urls: []
rules_of_engagement:
  max_requests_per_second: 5
{extra}
"""


def _scope(tmp_path: Path, *, allow_loopback: bool) -> Path:
    extra = "  allow_loopback_primary_target: true\n" if allow_loopback else ""
    path = tmp_path / "scope.yaml"
    path.write_text(
        SCOPE_TEMPLATE.format(extra=extra),
        encoding="utf-8",
    )
    return path


def test_loopback_primary_is_refused_by_default(tmp_path) -> None:
    scope = _scope(tmp_path, allow_loopback=False)
    result = check_scope_targets(scope, "curl http://127.0.0.1:3000/", "127.0.0.1")
    assert any("secondary-only" in error for error in result.errors), result.errors


def test_scope_opt_in_allows_a_loopback_lab(tmp_path) -> None:
    scope = _scope(tmp_path, allow_loopback=True)
    result = check_scope_targets(scope, "curl http://127.0.0.1:3000/", "127.0.0.1")
    assert not any("secondary-only" in error for error in result.errors), result.errors


def test_loopback_opt_in_does_not_allow_an_excluded_host(tmp_path) -> None:
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        SCOPE_TEMPLATE.format(extra="  allow_loopback_primary_target: true\n")
        + "exclusions:\n  ip_addresses:\n  - 127.0.0.1\n",
        encoding="utf-8",
    )
    result = check_scope_targets(scope, "curl http://127.0.0.1:3000/", "127.0.0.1")
    assert any("excluded" in error for error in result.errors), result.errors
