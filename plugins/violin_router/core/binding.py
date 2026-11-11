"""Binding checks between the router and the engagement state.

The router is additive: it never relaxes the guard's policy. What it does is
make the guard's own rule usable for skills that live outside the guard's
bundled catalog.

The rule stays the guard's: a vulnerability class may only be tested when the
PTT binds an approved skill for it. The router therefore asks the guard's
policy module which skill a class routes to, and refuses to hand out a
playbook whose class has no bound task.
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_GUARD_MODULE = "plugins.violin_guard.core.skills.skill_policy"


def _load_guard_policy() -> Any | None:
    """Import the guard's policy module, if it is importable from here."""
    if _GUARD_MODULE in sys.modules:
        return sys.modules[_GUARD_MODULE]
    try:
        spec = importlib.util.find_spec(_GUARD_MODULE)
    except (ImportError, ValueError):
        spec = None
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:
        return None
    sys.modules.setdefault(_GUARD_MODULE, module)
    return module


@dataclass(frozen=True)
class BindingCheck:
    """Whether a class may be tested with a given skill."""

    allowed: bool
    reason: str = ""
    expected_skill: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "expected_skill": self.expected_skill,
        }


def routed_skill(vulnerability_class: str, phase: str = "exploitation") -> str:
    """The guard's canonical skill for a vulnerability class (may be empty)."""
    policy = _load_guard_policy()
    if policy is None:
        return ""
    try:
        decision = policy.resolve_skill_route(phase, vulnerability_class, None)
    except Exception:
        return ""
    return str(decision.selected or "")


def check_binding(
    vulnerability_class: str,
    skill: str,
    phase: str = "exploitation",
    ptt_bound_classes: tuple[str, ...] = (),
) -> BindingCheck:
    """Check that a class may be tested with a skill.

    The rule is the guard's: a vulnerability class may only be tested when the
    engagement binds it. The router enforces the same rule for the playbooks
    it serves, which may come from a different pool than the guard's own.

    ``ptt_bound_classes`` lists the vulnerability classes the engagement's PTT
    currently binds. When it is empty the check is advisory — the guard itself
    is the component that refuses — and the router reports what the guard
    expects without refusing on its own.
    """
    policy = _load_guard_policy()
    if policy is None:
        return BindingCheck(allowed=True, reason="guard policy module unavailable")
    try:
        decision = policy.resolve_skill_route(phase, vulnerability_class, None)
    except Exception as exc:
        return BindingCheck(allowed=True, reason=f"guard policy error: {exc}")
    expected = str(decision.selected or "")
    if decision.mismatch_reasons:
        # The class is not one the guard knows: it cannot be routed, so the
        # router will not serve a playbook for it either.
        return BindingCheck(
            allowed=False,
            reason="; ".join(decision.mismatch_reasons),
            expected_skill=expected,
        )
    if ptt_bound_classes and vulnerability_class and vulnerability_class not in ptt_bound_classes:
        return BindingCheck(
            allowed=False,
            reason=(
                f"no PTT task binds vulnerability class {vulnerability_class!r}; "
                f"record the class and its skill in the PTT before testing it"
            ),
            expected_skill=expected,
        )
    return BindingCheck(allowed=True, expected_skill=expected)


def bound_classes(eng_dir: Path) -> tuple[str, ...]:
    """Read the vulnerability classes the engagement currently binds.

    The router reads the engagement documents the guard maintains, so the two
    agree on what is bound without the router owning any state of its own.

    The class lives on the hypothesis (``- **Vuln Class:** sqli``), and a task
    binds a hypothesis through the PTT binding store, so both are consulted.
    """
    classes: list[str] = []
    hypotheses = eng_dir / "hypotheses.md"
    if hypotheses.is_file():
        try:
            text = hypotheses.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        current: str | None = None
        for line in text.splitlines():
            heading = line.strip()
            if heading.startswith("### H-"):
                current = heading.split(":", 1)[0].replace("###", "").strip()
                continue
            if line.strip().startswith("- **Vuln Class:**"):
                value = line.split("**Vuln Class:**", 1)[1].strip()
                if value and value not in classes:
                    classes.append(value)
            elif line.strip().startswith("- **Status:**") and current:
                status = line.split("**Status:**", 1)[1].strip().lower()
                if status in {"closed", "rejected", "refuted", "resolved"}:
                    current = None
    return tuple(classes)
