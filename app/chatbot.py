"""Thetha conversation engine.

Deliberately offline and rule-based:
* zero running cost (sustainability) and works on a tiny server,
* survivor messages never leave our server (no third-party AI provider),
* deterministic, so every safety-critical reply can be tested.

"Intelligence" comes from: weighted multilingual intent scoring, typo-tolerant
fuzzy matching, a safety override (danger / self-harm always wins), language
detection, and a multi-turn danger-assessment flow based on known lethality
indicators (strangulation, weapons, threats to kill, escalation, separation).

Translations are short and must be reviewed by native speakers before launch.
"""
import difflib
import re
from dataclasses import asdict, dataclass, field

from .resources import HELPLINES, PROTECTION_ORDER_STEPS, pick

LANGUAGES = ("en", "zu", "xh", "af", "st")

LANG_MARKERS = {
    "zu": ["sawubona", "sanibonani", "ngiyashaywa", "uyangishaya", "ngisizeni", "ngicela", "usizo",
           "ngiyesaba", "ngiyabonga", "ngidlwenguliwe", "ngisengozini"],
    "xh": ["molo", "molweni", "ndincedeni", "ndibethwa", "ndiyoyika", "enkosi", "uncedo",
           "ndidlwenguliwe", "ndisengozini"],
    "af": ["hallo", "slaan my", "verkrag", "gevaar", "asseblief", "dankie", "bang vir",
           "beskermingsbevel", "my man slaan"],
    "st": ["dumela", "nthuse", "thuso", "ke a tshaba", "kea leboha", "o a nshapa", "ke kotsing",
           "betetswe"],
}

PHRASES = {
    "greeting": {
        "en": "Hello, I'm Thetha. You are safe to talk here.",
        "zu": "Sawubona, ngingu-Thetha. Uphephile ukukhuluma lapha.",
        "xh": "Molo, ndinguThetha. Ukhuselekile ukuthetha apha.",
        "af": "Hallo, ek is Thetha. Jy is veilig om hier te praat.",
        "st": "Dumela, ke nna Thetha. O bolokehile ho bua mona.",
    },
    "emergency": {
        "en": "If you are in danger right now, call 10111 or 112 immediately.",
        "zu": "Uma usengozini manje, shayela u-10111 noma u-112 manje.",
        "xh": "Ukuba usengozini ngoku, tsalela u-10111 okanye u-112 ngoko nangoko.",
        "af": "As jy nou in gevaar is, bel dadelik 10111 of 112.",
        "st": "Haeba o le kotsing hona jwale, letsetsa 10111 kapa 112 hang-hang.",
    },
}

# keyword -> weight. "word*" = prefix match, multi-word = phrase match.
INTENTS = {
    "emergency": {
        "in danger": 3, "help me now": 3, "he is here": 3, "she is here": 3, "kill me": 3,
        "going to kill": 3, "has a gun": 3, "has a knife": 3, "locked me in": 3,
        "hurting me now": 3, "beating me now": 3, "emergency": 3, "ngisizeni": 3,
        "ngisengozini": 3, "ndincedeni": 3, "ndisengozini": 3, "help my asseblief": 3,
        "help my nou": 3, "in gevaar": 3,
        "nthuse": 3, "ke kotsing": 3,
    },
    "suicide": {
        "kill myself": 4, "want to die": 4, "end my life": 4, "suicid*": 4,
        "no reason to live": 4, "better off dead": 4, "hurt myself": 4,
    },
    "sexual_assault": {
        "rape*": 3, "sexual assault": 3, "sexually assaulted": 3, "forced me to have sex": 3,
        "forced sex": 3, "molest*": 3, "touched me": 2, "ngidlwenguliwe": 3, "ukudlwengulwa": 3,
        "ndidlwenguliwe": 3, "verkrag*": 3, "betetswe": 3,
    },
    "abuse_disclosure": {
        "hit": 2, "hits": 2, "hitting": 2, "beat*": 2, "slap*": 2, "punch*": 2, "kick*": 2,
        "abus*": 2, "hurt*": 1, "violent": 2, "violence": 1, "chok*": 2, "strangl*": 2,
        "threat*": 1, "scared": 1, "afraid": 1, "controls me": 2, "shouts": 1, "insult*": 1,
        "bruise*": 2, "ngiyashaywa": 3, "uyangishaya": 3, "ngiyesaba": 2, "ndibethwa": 3,
        "ndiyoyika": 2, "slaan my": 3, "mishandel*": 3, "bang vir": 2, "o a nshapa": 3,
        "ke a tshaba": 2,
    },
    "protection_order": {
        "protection order": 4, "interdict": 3, "restraining order": 4, "court order": 3,
        "keep him away": 3, "keep her away": 3, "domestic violence act": 4, "magistrate": 2,
        "beskermingsbevel": 4,
    },
    "report_police": {
        "report": 2, "police": 2, "open a case": 3, "case number": 3, "saps": 2,
        "press charges": 3, "charges": 2, "arrest*": 2,
    },
    "safety_plan": {
        "safety plan": 4, "plan to leave": 3, "leave him": 3, "leave her": 3, "escape": 2,
        "get out": 2, "run away": 2, "where can i go": 2, "safe place": 2,
    },
    "shelter": {
        "shelter": 4, "place to stay": 3, "nowhere to go": 3, "homeless": 3,
        "kicked me out": 3, "safe house": 4,
    },
    "counselling": {
        "counsel*": 2, "therapy": 2, "therapist": 2, "talk to someone": 2, "depressed": 2,
        "anxious": 2, "trauma*": 2, "cant sleep": 2, "psycholog*": 2, "social worker": 2,
    },
    "callback": {
        "call me": 4, "callback": 4, "call back": 4, "talk to a counsellor": 4,
        "speak to a counsellor": 4, "real person": 3, "human": 3,
    },
    "rights": {
        "my rights": 3, "rights": 2, "is this abuse": 4, "is it abuse": 4, "is it normal": 3,
        "law": 1, "legal": 2, "lawyer": 2,
    },
    "children": {
        "child": 2, "children": 2, "kids": 2, "my son": 2, "my daughter": 2, "baby": 1,
        "minor": 2,
    },
    "financial_abuse": {
        "money": 2, "takes my money": 4, "salary": 2, "sassa": 2, "grant": 1, "bank card": 2,
        "wont let me work": 4, "financial*": 2,
    },
    "online_abuse": {
        "online": 2, "nudes": 4, "pictures of me": 3, "videos of me": 3, "stalk*": 3,
        "tracking my phone": 4, "revenge porn": 4, "sextortion": 4, "cyber*": 2, "whatsapp": 1,
        "facebook": 1, "tiktok": 1, "instagram": 1,
    },
    "help_someone": {
        "my friend": 3, "my sister": 3, "my mother": 3, "my mom": 3, "my neighbour": 3,
        "my neighbor": 3, "someone i know": 3, "my cousin": 3, "my colleague": 3,
        "help someone": 3,
    },
    "journal": {
        "evidence": 3, "journal": 3, "record": 2, "document": 2, "proof": 3, "diary": 3,
        "write down": 2,
    },
    "risk_check": {
        "am i safe": 4, "how dangerous": 4, "risk": 3, "danger assessment": 4, "assess*": 2,
    },
    "greeting": {
        "hi": 1, "hello": 1, "hey": 1, "good morning": 1, "good evening": 1, "sawubona": 1,
        "sanibonani": 1, "molo": 1, "molweni": 1, "hallo": 1, "dumela": 1, "howzit": 1,
    },
    "thanks": {
        "thank*": 1, "thanks": 1, "ngiyabonga": 1, "enkosi": 1, "dankie": 1, "kea leboha": 1,
    },
}

SAFETY_INTENTS = ("suicide", "emergency")  # always override everything else

YES = {"yes", "y", "yebo", "ja", "ewe", "ee", "e", "yep", "yeah"}
NO = {"no", "n", "cha", "nee", "hayi", "tjhe", "che", "nope"}
STOP = {"stop", "cancel", "exit", "quit", "skip"}

# Weights reflect lethality research: prior strangulation alone puts someone at high risk.
RISK_QUESTIONS = [
    ("Has the person ever choked or strangled you?", 6),
    ("Do they have, or have they threatened you with, a gun or knife?", 4),
    ("Have they threatened to kill you, your children, or themselves?", 3),
    ("Has the violence been getting worse or happening more often?", 2),
    ("Have you recently left them, or are you planning to leave?", 2),
    ("Are they extremely jealous or controlling (checking your phone, controlling where you go)?", 1),
]
HIGH_RISK, MEDIUM_RISK = 6, 3

MENU = ["I'm being abused", "Protection order", "Make a safety plan", "Check my risk",
        "Talk to a counsellor", "Is this abuse?"]


@dataclass
class BotReply:
    text: str
    intent: str
    language: str = "en"
    quick_replies: list = field(default_factory=list)
    resources: list = field(default_factory=list)
    risk_level: str | None = None
    link: dict | None = None
    state: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d.pop("state")
        return d


def normalize(text: str) -> str:
    text = text.lower().replace("'", "").replace("’", "")
    text = re.sub(r"[^\w\s*#]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _keyword_hit(keyword: str, padded: str, tokens: list[str]) -> bool:
    if " " in keyword:
        if f" {keyword} " in padded:
            return True
        if len(keyword) < 10:
            return False
        n = keyword.count(" ") + 1
        windows = (" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1))
        return any(difflib.SequenceMatcher(None, keyword, w).ratio() >= 0.88 for w in windows)
    if keyword.endswith("*"):
        stem = keyword[:-1]
        return any(t.startswith(stem) for t in tokens)
    if keyword in tokens:
        return True
    # typo tolerance ("protecton", "shelte") only for longer words
    return len(keyword) >= 6 and bool(difflib.get_close_matches(keyword, tokens, n=1, cutoff=0.85))


def score_intents(text: str) -> dict[str, int]:
    norm = normalize(text)
    padded, tokens = f" {norm} ", norm.split()
    scores = {}
    for intent, keywords in INTENTS.items():
        s = sum(w for kw, w in keywords.items() if _keyword_hit(kw, padded, tokens))
        if s:
            scores[intent] = s
    return scores


def classify(text: str) -> str:
    scores = score_intents(text)
    if not scores:
        return "unknown"
    for intent in SAFETY_INTENTS:
        if intent in scores:
            return intent
    return max(scores, key=scores.get)


EN_MARKERS = {"i", "the", "how", "what", "my", "is", "to", "do", "get", "me", "he", "she", "can", "a", "and"}


def detect_language(text: str, previous: str = "en") -> str:
    norm = f" {normalize(text)} "
    counts = {lang: sum(1 for m in markers if f" {m} " in norm) for lang, markers in LANG_MARKERS.items()}
    best = max(counts, key=counts.get)
    if counts[best]:
        return best
    if len(EN_MARKERS.intersection(norm.split())) >= 2:
        return "en"
    return previous


def _with_greeting(lang: str, text: str) -> str:
    return text if lang == "en" else f"{PHRASES['greeting'][lang]}\n\n{text}"


def _answer(intent: str, lang: str) -> BotReply:
    if intent == "emergency":
        local = PHRASES["emergency"][lang]
        head = local if lang == "en" else f"{local}\n{PHRASES['emergency']['en']}"
        return BotReply(
            f"{head}\n\nIf you can't speak, call 10111 and stay on the line, or dial *120*7867# "
            "for the GBV Command Centre. If you can, go to a neighbour or a public place. "
            "Press Quick Exit (or Esc twice) if someone is coming.",
            intent, lang, ["Make a safety plan", "Talk to a counsellor"],
            pick("saps", "emergency_mobile", "gbvcc"),
        )
    if intent == "suicide":
        return BotReply(
            "I'm really glad you told me. What you're feeling matters, and you don't have to "
            "carry it alone. Please talk to someone right now. SADAG's crisis line is free and "
            "open 24/7. If you are about to hurt yourself, call 10111 or 112.",
            intent, lang, ["Talk to a counsellor"], pick("sadag_suicide", "lifeline", "emergency_mobile"),
        )
    if intent == "sexual_assault":
        return BotReply(
            "I'm so sorry. What happened is not your fault. I believe you.\n\n"
            "Important: go to a clinic, hospital or Thuthuzela Care Centre as soon as possible, "
            "ideally within 72 hours. They can give you PEP (to prevent HIV) and emergency "
            "contraception, and they will look after you. You can get medical care even if you "
            "don't want to open a police case.\n\nIf you can, keep the clothes you were wearing "
            "in a paper bag and try not to wash before an exam, because this keeps evidence. "
            "But your health comes first.",
            intent, lang, ["Report to police", "Talk to a counsellor", "Keep evidence"],
            pick("gbvcc", "tears", "saps"),
        )
    if intent == "abuse_disclosure":
        return BotReply(
            "I'm really sorry this is happening to you. Thank you for trusting me. What you're "
            "going through is not your fault, and you deserve to be safe.\n\nI can help you:\n"
            "- check how dangerous your situation might be\n- make a safety plan\n"
            "- understand protection orders\n- keep a private, encrypted record of incidents",
            intent, lang, ["Check my risk", "Make a safety plan", "Protection order", "Keep evidence"],
            pick("gbvcc", "stop_gbv"),
        )
    if intent == "protection_order":
        steps = "\n".join(f"{i}. {s}" for i, s in enumerate(PROTECTION_ORDER_STEPS, 1))
        return BotReply(
            f"A protection order is a court order that tells the abuser to stop. "
            f"Here's how to get one:\n\n{steps}",
            intent, lang, ["Keep evidence", "Report to police", "Legal help"], pick("legal_aid", "gbvcc"),
        )
    if intent == "report_police":
        return BotReply(
            "You can open a case at any police station. You don't have to go to the one closest "
            "to where it happened.\n- Ask for a private room and, if you want, a female officer.\n"
            "- Ask for your case number (CAS number) and the investigating officer's name.\n"
            "- Domestic violence is a crime and the police must help you, even if the abuser is "
            "your partner.\nIf police refuse to help, call the GBV Command Centre.",
            intent, lang, ["Protection order", "Keep evidence"], pick("saps", "gbvcc"),
        )
    if intent == "safety_plan":
        return BotReply(
            "A safety plan helps you get ready in case you need to leave quickly. You can build "
            "one privately here. It is encrypted, and only you can see it.\nKey ideas: a code "
            "word for trusted people, a packed bag hidden somewhere safe, copies of your ID and "
            "documents, and knowing the safest way out of your home.",
            intent, lang, ["Check my risk", "Find a shelter"], pick("gbvcc"),
            link={"label": "Open my safety plan", "href": "/safety-plan"},
        )
    if intent == "shelter":
        return BotReply(
            "You don't have to stay somewhere unsafe. The GBV Command Centre can link you to a "
            "shelter (safe house) near you, 24/7. Shelter addresses are kept secret to protect the "
            "people there, so call them and they will place you.",
            intent, lang, ["Make a safety plan", "Talk to a counsellor"], pick("gbvcc", "stop_gbv"),
        )
    if intent == "counselling":
        return BotReply(
            "Talking to a trained counsellor can really help. It's free and confidential. You "
            "can call now, or ask a counsellor to call you back at a time that is safe for you.",
            intent, lang, ["Request a callback"], pick("lifeline", "gbvcc"),
            link={"label": "Request a safe callback", "href": "/callback"},
        )
    if intent == "callback":
        return BotReply(
            "A counsellor can call you back. You choose a safe time, and whether they may leave a "
            "message. Your number is encrypted and deleted after the case is closed.",
            intent, lang, [], pick("gbvcc"),
            link={"label": "Request a safe callback", "href": "/callback"},
        )
    if intent == "rights":
        return BotReply(
            "Abuse isn't only hitting. Under the Domestic Violence Act it includes:\n"
            "- physical abuse\n- sexual abuse\n- emotional, verbal and psychological abuse "
            "(insults, threats, humiliation)\n- economic abuse (controlling or taking your money)\n"
            "- intimidation, harassment and stalking\n- damage to your property\n\n"
            "If someone you live with or are in a relationship with does this, you can get a "
            "protection order. Love should never make you afraid.",
            intent, lang, ["Protection order", "I'm being abused"], pick("legal_aid", "gbvcc"),
        )
    if intent == "children":
        return BotReply(
            "Children's safety comes first. If a child is being abused or sees violence at home, "
            "Childline (116, free) can help. Children can also call them themselves. Protection "
            "orders can include your children.",
            intent, lang, ["Protection order", "Make a safety plan"], pick("childline", "gbvcc"),
        )
    if intent == "financial_abuse":
        return BotReply(
            "Taking your money, your SASSA grant or bank card, or stopping you from working is "
            "economic abuse, and the Domestic Violence Act covers it. A protection order can "
            "stop it. If you can, open a bank account the abuser doesn't know about, and keep "
            "your card and PIN safe.",
            intent, lang, ["Protection order", "Legal help"], pick("legal_aid", "gbvcc"),
        )
    if intent == "online_abuse":
        return BotReply(
            "Sharing intimate pictures of you without consent, or threatening to, is a crime "
            "under the Cybercrimes Act. Don't delete the messages: screenshot them with the date "
            "and the sender's details and keep them in your journal. Check your phone for "
            "location-sharing and apps you don't recognise. You can report it at the police and "
            "ask the platform to remove the content.",
            intent, lang, ["Keep evidence", "Report to police", "Protection order"], pick("saps", "gbvcc"),
        )
    if intent == "help_someone":
        return BotReply(
            "It's good that you care. How to help:\n- Listen without judging, and believe them.\n"
            "- Don't confront the abuser. That can make things more dangerous.\n"
            "- Share the GBV Command Centre number with them, in a safe way.\n"
            "- Let them make their own choices, and keep checking in.\n"
            "If they are in immediate danger, call 10111.",
            intent, lang, ["Is this abuse?", "Protection order"], pick("gbvcc", "saps"),
        )
    if intent == "journal":
        return BotReply(
            "Keeping a record of each incident (date, what happened, injuries, witnesses) "
            "makes it much easier to get a protection order or open a case. Thetha's journal "
            "is encrypted. Not even our staff can read it, and you can delete it at any time.",
            intent, lang, ["Protection order"], [],
            link={"label": "Open my private journal", "href": "/journal"},
        )
    if intent == "greeting":
        return BotReply(
            f"{PHRASES['greeting'][lang]}\n\nI don't save what you type here. How can I help "
            "you today?", intent, lang, MENU, [],
        )
    if intent == "thanks":
        return BotReply(
            "You're welcome. Reaching out takes courage. I'm here whenever you need me.",
            intent, lang, MENU[:3], pick("gbvcc"),
        )
    return BotReply(
        "I'm not sure I understood, sorry. You can ask me about any of these, or call the "
        "GBV Command Centre to talk to a person:",
        "unknown", lang, MENU, pick("gbvcc"),
    )


def _risk_question(step: int) -> str:
    q, _ = RISK_QUESTIONS[step]
    return f"Question {step + 1} of {len(RISK_QUESTIONS)}: {q}\n(Answer yes or no, or 'stop' to end.)"


def _risk_result(score: int, lang: str) -> BotReply:
    note = ("\n\nThis check is not a prediction. You know your situation best, so trust your "
            "instincts.")
    if score >= HIGH_RISK:
        return BotReply(
            "Your answers show signs that you may be in serious danger. People in situations "
            "like yours have been badly hurt. Please don't face this alone. Call the GBV Command "
            "Centre today, make a safety plan, and consider a protection order." + note,
            "risk_result", lang, ["Make a safety plan", "Protection order", "Request a callback"],
            pick("gbvcc", "saps"), risk_level="high",
        )
    if score >= MEDIUM_RISK:
        return BotReply(
            "Your answers show some warning signs. Abuse often gets worse over time. A "
            "safety plan and a talk with a counsellor could really help." + note,
            "risk_result", lang, ["Make a safety plan", "Talk to a counsellor"], pick("gbvcc"),
            risk_level="medium",
        )
    return BotReply(
        "Your answers show fewer of the known danger signs right now. But any abuse is "
        "serious, and you deserve support. Things can change quickly, so keep a safety plan "
        "ready." + note,
        "risk_result", lang, ["Make a safety plan", "Is this abuse?"], pick("gbvcc"),
        risk_level="low",
    )


def respond(message: str, state: dict | None = None) -> BotReply:
    """Pure function: (message, state) -> reply with new state. No I/O."""
    state = dict(state or {}) if isinstance(state, dict) else {}
    if state.get("lang") not in LANGUAGES:
        state["lang"] = "en"
    step, score = state.get("step"), state.get("score")
    if state.get("flow") == "risk" and not (isinstance(step, int) and 0 <= step < len(RISK_QUESTIONS)
                                            and isinstance(score, int) and score >= 0):
        state = {"lang": state["lang"]}  # stale or forged state: start clean
    previous_lang = state["lang"]
    lang = detect_language(message, previous_lang)
    state["lang"] = lang if lang in LANGUAGES else "en"
    norm = normalize(message)
    intent = classify(message)

    # Safety override: even mid-assessment, danger or self-harm is answered first.
    if intent in SAFETY_INTENTS:
        state.pop("flow", None)
        reply = _answer(intent, lang)
        reply.state = state
        return reply

    if state.get("flow") == "risk":
        if norm in STOP:
            state = {"lang": lang}
            reply = BotReply("Okay, I've stopped the check. What would you like to do?", "risk_cancel",
                             lang, MENU)
            reply.state = state
            return reply
        if norm in YES or norm in NO:
            step, score = state.get("step", 0), state.get("score", 0)
            if norm in YES:
                score += RISK_QUESTIONS[step][1]
            step += 1
            if step >= len(RISK_QUESTIONS):
                reply = _risk_result(score, lang)
                reply.state = {"lang": lang}
                return reply
            state.update(step=step, score=score)
            reply = BotReply(_risk_question(step), "risk_question", lang, ["Yes", "No", "Stop"])
            reply.state = state
            return reply
        if intent == "unknown":
            reply = BotReply("Please answer yes or no, or say 'stop'.\n\n" + _risk_question(state.get("step", 0)),
                             "risk_question", lang, ["Yes", "No", "Stop"])
            reply.state = state
            return reply
        state.pop("flow", None)  # user changed topic; drop the flow

    if intent == "risk_check":
        state.update(flow="risk", step=0, score=0)
        reply = BotReply(
            "I'll ask you 6 short yes/no questions. Your answers are not saved.\n\n" + _risk_question(0),
            "risk_question", lang, ["Yes", "No", "Stop"],
        )
        reply.state = state
        return reply

    reply = _answer(intent, lang)
    if intent != "greeting" and lang != "en" and lang != previous_lang:
        reply.text = _with_greeting(lang, reply.text)  # greet once when the user switches language
    reply.state = state
    return reply


QUICK_REPLY_ALIASES = {
    "check my risk": "am i safe",
    "make a safety plan": "safety plan",
    "talk to a counsellor": "counselling",
    "request a callback": "callback",
    "keep evidence": "evidence journal",
    "legal help": "lawyer legal",
    "find a shelter": "shelter",
    "report to police": "open a case police",
    "i'm being abused": "abuse",
}


def expand_quick_reply(message: str) -> str:
    return QUICK_REPLY_ALIASES.get(message.strip().lower(), message)


__all__ = ["respond", "classify", "detect_language", "expand_quick_reply", "BotReply", "HELPLINES"]
