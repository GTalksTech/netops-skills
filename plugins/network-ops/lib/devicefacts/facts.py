# ============================================================
# Script:       facts.py
# Purpose:      The shape of device facts read from one config, shared by every platform
#               reader: interfaces (with the lines that make one internet-facing) and
#               features that are on, off or unknown (with the lines that prove it).
# Author:       G Talks Tech
# ============================================================
from .mask import mask

ON, OFF, UNKNOWN = "on", "off", "unknown"
STATES = (ON, OFF, UNKNOWN)
MAX_PROOF = 6


def proof(lines):
    """Config or show lines shown as proof: secrets masked, at most MAX_PROOF lines."""
    return [mask(l) for l in list(lines or [])[:MAX_PROOF]]


def new_facts():
    """Facts from one config. internet_interfaces lists names; each interface dict that faces
    the internet carries internet_why and internet_evidence (the lines that decided it)."""
    return {"interfaces": [], "internet_interfaces": [], "features": {}, "notes": [], "hostname": None}


def feature(facts, name, on, internet=False, where=None, evidence=None, detail=None):
    """Record one feature. on: True (on), False (off) or None (unknown: the saved output cannot
    say). Unknown is never off: its internet flag is None too. evidence: the config or show lines
    that decided it (for 'off by absence', the 'no ...' lines when there are any); detail: one
    sentence saying how it was decided."""
    state = UNKNOWN if on is None else ON if on else OFF
    facts["features"][name] = {"state": state, "internet": None if state == UNKNOWN else bool(on and internet),
                               "where": where, "evidence": proof(evidence), "detail": detail}


def unknown(facts, name, detail):
    feature(facts, name, None, detail=detail)


def all_unknown(facts, detail):
    """Mark every feature already read as unknown: the config they came from cannot be trusted
    (no interfaces parsed, a parser that does not read this format)."""
    for name in list(facts["features"]):
        unknown(facts, name, detail)


def internet_evidence(itf, evidence, why):
    """Record why itf (an interface or zone dict) faces the internet: a short reason and the
    lines that show it. The reader lists its name in facts['internet_interfaces'] itself."""
    itf["internet_why"] = why
    itf["internet_evidence"] = proof(evidence)
