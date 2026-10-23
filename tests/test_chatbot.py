"""Conversation engine: positive and negative tests (no web server needed)."""
import pytest

from app.chatbot import RISK_QUESTIONS, classify, detect_language, respond

pos = pytest.mark.positive
neg = pytest.mark.negative


def run(*messages):
    state, reply = {}, None
    for m in messages:
        reply = respond(m, state)
        state = reply.state
    return reply


# ---------------------------------------------------------------- positive
@pos
@pytest.mark.parametrize("text, intent", [
    ("hello", "greeting"),
    ("my husband hits me", "abuse_disclosure"),
    ("how do I get a protection order", "protection_order"),
    ("I was raped last night", "sexual_assault"),
    ("I want to open a case at the police", "report_police"),
    ("I need a shelter, I have nowhere to go", "shelter"),
    ("he takes my money and my sassa card", "financial_abuse"),
    ("he is sharing my nudes on whatsapp", "online_abuse"),
    ("my friend is being beaten by her boyfriend", "help_someone"),
    ("is this abuse?", "rights"),
    ("can someone call me back", "callback"),
    ("I want to keep evidence", "journal"),
    ("thank you", "thanks"),
])
def test_classifies_common_needs(text, intent):
    assert classify(text) == intent


@pos
def test_emergency_returns_police_numbers_first():
    r = respond("he has a knife and is going to kill me")
    assert r.intent == "emergency"
    assert "10111" in r.text
    assert r.resources[0]["number"] == "10111"


@pos
def test_suicide_risk_gets_crisis_line():
    r = respond("I just want to die")
    assert r.intent == "suicide"
    assert any(h["number"] == "0800 567 567" for h in r.resources)


@pos
def test_sexual_assault_mentions_pep_within_72_hours():
    r = respond("I was raped")
    assert "72 hours" in r.text and "PEP" in r.text


@pos
@pytest.mark.parametrize("text, lang", [
    ("Sawubona ngiyashaywa", "zu"),
    ("Molo ndibethwa", "xh"),
    ("Hallo, my man slaan my", "af"),
    ("Dumela, o a nshapa", "st"),
    ("Hello I need help", "en"),
])
def test_detects_south_african_languages(text, lang):
    assert detect_language(text) == lang


@pos
def test_isizulu_abuse_disclosure_understood_and_greeted_in_isizulu():
    r = respond("ngiyashaywa")
    assert r.intent == "abuse_disclosure"
    assert r.language == "zu"
    assert "Sawubona" in r.text


@pos
def test_switches_back_to_english():
    r = run("ngiyashaywa", "how do I get a protection order")
    assert r.language == "en" and "Sawubona" not in r.text


@neg
def test_language_greeting_not_repeated_every_message():
    r = run("ngiyashaywa", "protection order")
    assert r.language == "zu" and "Sawubona" not in r.text


@pos
def test_isizulu_emergency_reply_in_isizulu():
    r = respond("ngisizeni ngisengozini")
    assert r.intent == "emergency"
    assert "shayela" in r.text


@pos
def test_typo_tolerance():
    assert classify("how to get a protecton order") == "protection_order"
    assert classify("i need a sheltr") == "shelter"


@pos
def test_full_risk_assessment_high():
    r = run("am i safe", *["yes"] * len(RISK_QUESTIONS))
    assert r.risk_level == "high"
    assert r.state.get("flow") is None


@pos
def test_strangulation_alone_is_high_risk():
    r = run("check my risk", "yes", *["no"] * (len(RISK_QUESTIONS) - 1))
    assert r.risk_level == "high"


@pos
def test_full_risk_assessment_low():
    r = run("am i safe", *["no"] * len(RISK_QUESTIONS))
    assert r.risk_level == "low"


@pos
def test_risk_assessment_accepts_isizulu_yes():
    r = run("am i safe", "yebo", "cha", "cha", "cha", "cha", "cha")
    assert r.risk_level == "high"


# ---------------------------------------------------------------- negative
@neg
def test_gibberish_falls_back_safely_with_helpline():
    r = respond("qwxz plorf")
    assert r.intent == "unknown"
    assert r.resources and r.resources[0]["number"].replace(" ", "") == "0800428428"
    assert r.quick_replies


@neg
def test_help_my_friend_is_not_misread_as_afrikaans_emergency():
    assert classify("can you help my friend") == "help_someone"
    assert detect_language("can you help my friend") == "en"


@neg
def test_danger_overrides_an_unfinished_risk_check():
    r = run("am i safe", "yes", "he is here with a gun, help me now")
    assert r.intent == "emergency"
    assert "flow" not in r.state


@neg
def test_unclear_answer_during_risk_check_reprompts_without_advancing():
    r = run("am i safe", "maybe?")
    assert r.intent == "risk_question"
    assert r.state["step"] == 0
    assert "yes or no" in r.text


@neg
def test_stop_cancels_risk_check():
    r = run("am i safe", "yes", "stop")
    assert r.intent == "risk_cancel"
    assert "flow" not in r.state and "score" not in r.state


@neg
def test_html_in_message_is_not_echoed_back():
    r = respond("<script>alert(1)</script>")
    assert "<script>" not in r.text


@neg
@pytest.mark.parametrize("text", ["", "   ", "!!!", "😀😀"])
def test_empty_or_symbol_only_input_does_not_crash(text):
    assert respond(text).intent == "unknown"


@neg
def test_state_tampering_with_bad_step_is_contained():
    # A forged or stale state must not crash the engine with IndexError.
    r = respond("yes", {"flow": "risk", "step": 99, "score": 0})
    assert r.intent in ("risk_result", "risk_question", "unknown")
