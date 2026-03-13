"""Medically sensitive PII recognizers: GENDER, RELIGION."""
from dataguard_deid.core.base_recognizer import PatternRecognizer

from dataguard_deid.config.scoring import SCORE_PROFILES
from dataguard_deid.patterns.dutch_patterns import (
    GENDER_REGEX_NL, RELIGIOUS_REGEX_NL,
)
from dataguard_deid.recognizers._helpers import _p

_GE = SCORE_PROFILES["GENDER"]
_RE = SCORE_PROFILES["RELIGION"]


class NlGenderRecognizer(PatternRecognizer):
    PATTERNS = [_p("gender_nl", GENDER_REGEX_NL, _GE.base)]
    CONTEXT = [
        "geslacht", "gender", "sekse", "aanhef",
        "m/v/x", "man", "vrouw", "genderidentiteit",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="GENDER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlReligionRecognizer(PatternRecognizer):
    PATTERNS = [_p("religion_nl", RELIGIOUS_REGEX_NL, _RE.base)]
    CONTEXT = [
        "geloof", "religie", "godsdienst", "kerk",
        "moskee", "levensbeschouwing", "overtuiging", "gezindte",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="RELIGION",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
