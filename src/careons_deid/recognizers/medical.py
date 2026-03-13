"""Medically sensitive PII recognizers: GENDER, BLOOD_TYPE, RELIGION."""
from careons_deid.core.base_recognizer import PatternRecognizer

from careons_deid.config.scoring import SCORE_PROFILES
from careons_deid.patterns.dutch_patterns import (
    GENDER_REGEX_NL, BLOOD_TYPE_REGEX, RELIGIOUS_REGEX_NL,
)
from careons_deid.recognizers._helpers import _p

_GE = SCORE_PROFILES["GENDER"]
_BL = SCORE_PROFILES["BLOOD_TYPE"]
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


class NlBloodTypeRecognizer(PatternRecognizer):
    PATTERNS = [_p("blood_type", BLOOD_TYPE_REGEX, _BL.base)]
    CONTEXT = ["bloedgroep", "bloedtype", "resusfactor", "rhesus", "bloed", "donor"]

    def __init__(self):
        super().__init__(
            supported_entity="BLOOD_TYPE",
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
