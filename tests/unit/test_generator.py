"""Unit tests for the password generator, including property-based tests."""

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pm import generator
from pm.generator import ClassSpec, Policy, PolicyError

pytestmark = pytest.mark.unit

CLASS_NAMES = ("lowercase", "uppercase", "digits", "symbols")


def _count(pw, chars):
    return sum(c in chars for c in pw)


# --- example-based -----------------------------------------------------------
def test_length_and_minimums_honored():
    policy = Policy(
        length=16,
        classes={
            "lowercase": ClassSpec(min=1),
            "uppercase": ClassSpec(min=1),
            "digits": ClassSpec(min=2),
            "symbols": ClassSpec(min=1, max=4, char_set="!@#$%"),
        },
    )
    for _ in range(200):
        pw = generator.generate(policy)
        assert len(pw) == 16
        assert _count(pw, generator.DEFAULT_SETS["lowercase"]) >= 1
        assert _count(pw, generator.DEFAULT_SETS["uppercase"]) >= 1
        assert _count(pw, generator.DEFAULT_SETS["digits"]) >= 2
        assert 1 <= _count(pw, "!@#$%") <= 4


def test_max_zero_excludes_class():
    policy = Policy(
        length=12,
        classes={"lowercase": ClassSpec(min=1), "digits": ClassSpec(min=0, max=0)},
    )
    for _ in range(50):
        assert _count(generator.generate(policy), generator.DEFAULT_SETS["digits"]) == 0


def test_exclude_chars_never_appear():
    policy = Policy(length=20, classes={"lowercase": ClassSpec(min=1)}, exclude_chars="aeiou")
    for _ in range(50):
        assert not (set(generator.generate(policy)) & set("aeiou"))


def test_avoid_ambiguous():
    policy = Policy(
        length=30,
        classes={n: ClassSpec(min=1) for n in ("lowercase", "uppercase", "digits")},
        avoid_ambiguous=True,
    )
    for _ in range(50):
        assert not (set(generator.generate(policy)) & set(generator.AMBIGUOUS))


def test_exact_count():
    policy = Policy(length=10, classes={"digits": ClassSpec(min=3, max=3), "lowercase": ClassSpec(min=1)})
    for _ in range(50):
        assert _count(generator.generate(policy), generator.DEFAULT_SETS["digits"]) == 3


def test_custom_class_set():
    policy = Policy(length=8, classes={"lowercase": ClassSpec(min=8, char_set="ab")})
    assert set(generator.generate(policy)) <= set("ab")


def test_is_not_deterministic():
    policy = generator.preset("default")
    assert len({generator.generate(policy) for _ in range(20)}) > 1


# --- infeasible policies -----------------------------------------------------
def test_infeasible_min_exceeds_length():
    with pytest.raises(PolicyError):
        generator.generate(Policy(length=4, classes={"digits": ClassSpec(min=5)}))


def test_infeasible_max_below_length():
    with pytest.raises(PolicyError):
        generator.generate(Policy(length=10, classes={"digits": ClassSpec(min=0, max=3)}))


def test_required_class_empty_after_exclusion():
    with pytest.raises(PolicyError):
        generator.generate(
            Policy(length=8, classes={"digits": ClassSpec(min=1)}, exclude_chars="0123456789")
        )


def test_zero_length_rejected():
    with pytest.raises(PolicyError):
        generator.generate(Policy(length=0, classes={"digits": ClassSpec(min=0)}))


def test_max_less_than_min_rejected():
    with pytest.raises(PolicyError):
        generator.generate(Policy(length=5, classes={"digits": ClassSpec(min=3, max=2)}))


def test_unknown_class_without_set_rejected():
    with pytest.raises(PolicyError):
        generator.generate(Policy(length=5, classes={"weird": ClassSpec(min=1)}))


# --- serialization & presets -------------------------------------------------
def test_policy_serialization_roundtrip():
    policy = generator.preset("compat")
    assert generator.policy_from_dict(generator.policy_to_dict(policy)) == policy


@pytest.mark.parametrize("name", generator.PRESET_NAMES)
def test_presets_generate_expected_length(name):
    policy = generator.preset(name)
    assert len(generator.generate(policy)) == policy.length


def test_unknown_preset_rejected():
    with pytest.raises(PolicyError):
        generator.preset("does-not-exist")


# --- property-based ----------------------------------------------------------
@st.composite
def policies(draw):
    length = draw(st.integers(min_value=1, max_value=40))
    classes = {}
    for name in CLASS_NAMES:
        if not draw(st.booleans()):
            continue
        mn = draw(st.integers(min_value=0, max_value=10))
        mx = draw(st.one_of(st.none(), st.integers(min_value=mn, max_value=mn + 10)))
        classes[name] = ClassSpec(min=mn, max=mx)
    return Policy(length=length, classes=classes, avoid_ambiguous=draw(st.booleans()))


@settings(max_examples=300, deadline=None)
@given(policy=policies())
def test_generated_password_always_satisfies_feasible_policy(policy):
    try:
        effective = generator.validate(policy)
    except PolicyError:
        assume(False)  # only assert on feasible policies
        return

    pw = generator.generate(policy)

    assert len(pw) == policy.length
    allowed = set().union(*(set(s) for s in effective.values()))
    assert set(pw) <= allowed  # only allowed characters
    for name, spec in policy.classes.items():
        cnt = _count(pw, effective[name])
        assert cnt >= spec.min
        if spec.max is not None:
            assert cnt <= spec.max


@settings(max_examples=200, deadline=None)
@given(policy=policies())
def test_serialization_roundtrip_property(policy):
    assert generator.policy_from_dict(generator.policy_to_dict(policy)) == policy
