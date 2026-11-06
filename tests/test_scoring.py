import pytest

from phishing_detector.checks import attachments, auth, content, history, links, sender, wording
from phishing_detector.models import Finding
from phishing_detector.scoring import WEIGHTS, analyze, score_of, to_indicators, verdict_for


def test_thresholds():
    assert verdict_for(0) == "likely_legitimate"
    assert verdict_for(24) == "likely_legitimate"
    assert verdict_for(25) == "suspicious"
    assert verdict_for(49) == "suspicious"
    assert verdict_for(50) == "phishing"
    assert verdict_for(100) == "phishing"


def test_score_is_the_sum_of_weights_capped_at_100():
    two = to_indicators([Finding("links.ip_host", "r"), Finding("wording.urgency", "r")])
    assert score_of(two) == WEIGHTS["links.ip_host"] + WEIGHTS["wording.urgency"]
    many = to_indicators([Finding(i, "r") for i in ("attach.executable", "attach.double_extension", "links.password_form")])
    assert score_of(many) == 100


def test_indicators_get_category_and_weight_and_are_sorted_by_weight():
    indicators = to_indicators([Finding("wording.urgency", "r", ("urgent",)), Finding("attach.executable", "r")])
    assert [i.id for i in indicators] == ["attach.executable", "wording.urgency"]
    assert indicators[1].category == "wording"
    assert indicators[1].weight == WEIGHTS["wording.urgency"]
    assert indicators[1].evidence == ("urgent",)


def test_unknown_signal_is_an_error():
    with pytest.raises(ValueError):
        to_indicators([Finding("no.such_signal", "r")])


FAMILIES = [auth, sender, links, wording, attachments, content, history]


def test_every_signal_a_check_can_emit_has_a_weight():
    for module in FAMILIES:
        assert set(module.SIGNALS) <= set(WEIGHTS), module.__name__


def test_weights_are_whole_numbers_within_range():
    assert all(isinstance(w, int) and 0 <= w <= 100 for w in WEIGHTS.values())


def test_analyze_returns_a_complete_result():
    result = analyze(b"Hello team, the notes from today's meeting are below.\n")
    assert result.input_type == "body_only"
    assert result.verdict == "likely_legitimate"
    assert result.score == 0
    assert result.sender_domain is None
    assert len(result.email_sha256) == 64
    assert any("Body text only" in note for note in result.notes)


def test_the_weight_table_has_exactly_the_signals_the_checks_emit():
    emitted = set().union(*(module.SIGNALS for module in FAMILIES))
    assert emitted == set(WEIGHTS)
