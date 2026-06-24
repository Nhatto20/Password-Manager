"""Password generator — pure, no I/O.

A policy is a target length plus per-character-class min/max counts. Generation
uses "guarantee-then-fill": place each class's required minimum first, fill the
rest from classes not yet at their max, then CSPRNG-shuffle. This guarantees the
result satisfies the policy by construction, in a single pass.

All randomness comes from `secrets` (a CSPRNG), never `random`.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

# Default character set per class. Classes are disjoint so a generated
# character maps unambiguously back to the class that produced it.
DEFAULT_SETS: dict[str, str] = {
    "lowercase": "abcdefghijklmnopqrstuvwxyz",
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*-_=+",
}

# Characters easily confused by humans, dropped when avoid_ambiguous is set.
AMBIGUOUS = "0O1lI"


class PolicyError(ValueError):
    """A policy is malformed or impossible to satisfy."""


@dataclass(frozen=True)
class ClassSpec:
    """Count constraints for one character class.

    min: required count (>= 0). max: cap (None == unbounded).
    char_set: override the default set for this class ("" == use default).
    """

    min: int = 0
    max: int | None = None
    char_set: str = ""


@dataclass(frozen=True)
class Policy:
    length: int
    classes: dict[str, ClassSpec] = field(default_factory=dict)
    exclude_chars: str = ""
    avoid_ambiguous: bool = False


# --- effective alphabets -----------------------------------------------------
def _effective_set(name: str, spec: ClassSpec, policy: Policy) -> str:
    base = spec.char_set or DEFAULT_SETS.get(name)
    if base is None:
        raise PolicyError(f"unknown character class {name!r} with no custom set")
    remove = set(policy.exclude_chars)
    if policy.avoid_ambiguous:
        remove |= set(AMBIGUOUS)
    return "".join(c for c in base if c not in remove)


# --- validation --------------------------------------------------------------
def validate(policy: Policy) -> dict[str, str]:
    """Check feasibility; raise PolicyError if impossible.

    Returns the effective (post-exclusion) character set per class so callers
    don't recompute it.
    """
    if policy.length < 1:
        raise PolicyError("length must be at least 1")

    effective: dict[str, str] = {}
    total_min = 0
    total_max = 0  # treating unbounded max as the full length
    for name, spec in policy.classes.items():
        if spec.min < 0:
            raise PolicyError(f"{name}: min must be >= 0")
        if spec.max is not None and spec.max < spec.min:
            raise PolicyError(f"{name}: max ({spec.max}) < min ({spec.min})")
        chars = _effective_set(name, spec, policy)
        if spec.min > 0 and not chars:
            raise PolicyError(f"{name}: requires {spec.min} char(s) but its set is empty")
        effective[name] = chars
        total_min += spec.min
        total_max += policy.length if spec.max is None else spec.max

    if total_min > policy.length:
        raise PolicyError(
            f"sum of minimums ({total_min}) exceeds length ({policy.length})"
        )
    if total_max < policy.length:
        raise PolicyError(
            f"length ({policy.length}) cannot be reached within class maximums "
            f"(capacity {total_max})"
        )
    # Need at least one usable class to fill beyond the guaranteed minimums.
    if total_min < policy.length and not any(effective.values()):
        raise PolicyError("no characters available to generate from")
    return effective


# --- generation --------------------------------------------------------------
def generate(policy: Policy) -> str:
    effective = validate(policy)
    counts: dict[str, int] = {name: 0 for name in policy.classes}
    chars: list[str] = []

    # Step 1: satisfy every minimum.
    for name, spec in policy.classes.items():
        for _ in range(spec.min):
            chars.append(secrets.choice(effective[name]))
            counts[name] += 1

    # Step 2: fill the remainder from classes not yet at their max.
    while len(chars) < policy.length:
        eligible = [
            name
            for name, spec in policy.classes.items()
            if effective[name] and (spec.max is None or counts[name] < spec.max)
        ]
        if not eligible:  # validate() makes this unreachable; guard anyway
            raise PolicyError("ran out of eligible characters while filling")
        pool = "".join(effective[name] for name in eligible)
        choice = secrets.choice(pool)
        chars.append(choice)
        for name in eligible:  # attribute the char to its (disjoint) class
            if choice in effective[name]:
                counts[name] += 1
                break

    # Step 3: shuffle so the guaranteed-minimum chars aren't positional.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# --- serialization (for storage in the entry's gen_policy column) ------------
def policy_to_dict(policy: Policy) -> dict[str, Any]:
    classes: dict[str, Any] = {}
    for name, spec in policy.classes.items():
        entry: dict[str, Any] = {"min": spec.min, "max": spec.max}
        if spec.char_set:
            entry["set"] = spec.char_set
        classes[name] = entry
    return {
        "length": policy.length,
        "classes": classes,
        "exclude_chars": policy.exclude_chars,
        "avoid_ambiguous": policy.avoid_ambiguous,
    }


def policy_from_dict(data: dict[str, Any]) -> Policy:
    classes = {
        name: ClassSpec(
            min=int(spec.get("min", 0)),
            max=None if spec.get("max") is None else int(spec["max"]),
            char_set=spec.get("set", ""),
        )
        for name, spec in data.get("classes", {}).items()
    }
    return Policy(
        length=int(data["length"]),
        classes=classes,
        exclude_chars=data.get("exclude_chars", ""),
        avoid_ambiguous=bool(data.get("avoid_ambiguous", False)),
    )


# --- presets -----------------------------------------------------------------
def preset(name: str) -> Policy:
    if name == "default":
        return Policy(
            length=20,
            classes={
                "lowercase": ClassSpec(min=1),
                "uppercase": ClassSpec(min=1),
                "digits": ClassSpec(min=1),
                "symbols": ClassSpec(min=1),
            },
        )
    if name == "compat":
        return Policy(
            length=16,
            classes={
                "lowercase": ClassSpec(min=1),
                "uppercase": ClassSpec(min=1),
                "digits": ClassSpec(min=1),
                "symbols": ClassSpec(min=1, max=4, char_set="!@#$%"),
            },
            avoid_ambiguous=True,
        )
    if name == "alphanumeric":
        return Policy(
            length=20,
            classes={
                "lowercase": ClassSpec(min=1),
                "uppercase": ClassSpec(min=1),
                "digits": ClassSpec(min=1),
            },
        )
    if name == "pin":
        return Policy(length=6, classes={"digits": ClassSpec(min=4, max=6)})
    raise PolicyError(f"unknown preset {name!r}")


PRESET_NAMES = ("default", "compat", "alphanumeric", "pin")
