"""CVE lookup: the advisory data the router returns must be usable."""

from __future__ import annotations

from plugins.violin_router.core.cve import ECOSYSTEM_HINTS, ecosystems_for, lookup, query_osv


def test_technology_maps_to_an_ecosystem() -> None:
    assert ecosystems_for("express") == ("npm",)
    assert ecosystems_for("django") == ("PyPI",)
    assert "Maven" in ecosystems_for("log4j")
    assert ecosystems_for("unknown-thing-xyz") == ()


def test_ecosystem_hints_are_consistent() -> None:
    for technology, ecosystems in ECOSYSTEM_HINTS.items():
        assert ecosystems, f"{technology} maps to no ecosystem"
        assert all(isinstance(item, str) and item for item in ecosystems)


def test_lookup_without_input_is_rejected() -> None:
    result = lookup("", version="")
    assert result["advisories"] == []
    assert "nothing to look up" in result["note"]


def test_query_osv_returns_known_advisories() -> None:
    advisories = query_osv("lodash", "npm", "4.17.15")
    assert advisories, "OSV returned nothing for a known-vulnerable lodash"
    identifiers = {entry.id for entry in advisories} | {
        alias for entry in advisories for alias in entry.aliases
    }
    assert any("CVE" in identifier for identifier in identifiers), identifiers


def test_lookup_shape_is_stable() -> None:
    result = lookup("express", version="4.17.1")
    assert result["technology"] == "express"
    assert result["package"] == "express"
    assert isinstance(result["advisories"], list)
    for advisory in result["advisories"]:
        assert advisory["id"]
        assert "summary" in advisory
