"""
Recognizer registry for careons_deid.

Imports every domain recognizer and exports:
  - ALL_REGEX_RECOGNIZERS  – ordered list of recognizer *classes* (not instances)
    passed to GuardAnalyzer at engine initialisation.
  - Individual classes re-exported for direct import convenience.
"""

from careons_deid.recognizers.temporal import NlDateRecognizer, NlTimeRecognizer
from careons_deid.recognizers.contact import (
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlZipcodeRecognizer,
    NlUrlRecognizer,
)
from careons_deid.recognizers.identity import (
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlImeiRecognizer,
)
from careons_deid.recognizers.financial import (
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    NlCvvRecognizer,
    NlZorgpolisRecognizer,
    NlUnknownNumberRecognizer,
)
from careons_deid.recognizers.network import NlIpRecognizer, NlMacAddressRecognizer
from careons_deid.recognizers.medical import (
    NlGenderRecognizer,
    NlBloodTypeRecognizer,
    NlReligionRecognizer,
)
from careons_deid.recognizers.geo import NlGpsRecognizer, NlLicencePlateRecognizer
from careons_deid.recognizers.spacy_recognizer import NlNerRecognizer

ALL_REGEX_RECOGNIZERS = [
    # ── Temporal ─────────────────────────────────────────────────
    NlDateRecognizer,
    NlTimeRecognizer,
    # ── Contact ──────────────────────────────────────────────────
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlZipcodeRecognizer,
    NlUrlRecognizer,
    # ── Identity ─────────────────────────────────────────────────
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlImeiRecognizer,
    # ── Financial ────────────────────────────────────────────────
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    NlCvvRecognizer,
    NlZorgpolisRecognizer,
    # ── Network ──────────────────────────────────────────────────
    NlIpRecognizer,
    NlMacAddressRecognizer,
    # ── Medical / Sensitive ──────────────────────────────────────
    NlGenderRecognizer,
    NlBloodTypeRecognizer,
    NlReligionRecognizer,
    # ── Geo ──────────────────────────────────────────────────────
    NlGpsRecognizer,
    NlLicencePlateRecognizer,
    # ── Catch-all (must be last) ─────────────────────────────────
    NlUnknownNumberRecognizer,
]

__all__ = [
    "ALL_REGEX_RECOGNIZERS",
    "NlNerRecognizer",
    "NlDateRecognizer",
    "NlTimeRecognizer",
    "NlPhoneRecognizer",
    "NlEmailRecognizer",
    "NlZipcodeRecognizer",
    "NlUrlRecognizer",
    "NlBsnRecognizer",
    "NlPassportRecognizer",
    "NlImeiRecognizer",
    "NlIbanRecognizer",
    "NlCreditCardRecognizer",
    "NlCvvRecognizer",
    "NlZorgpolisRecognizer",
    "NlIpRecognizer",
    "NlMacAddressRecognizer",
    "NlGenderRecognizer",
    "NlBloodTypeRecognizer",
    "NlReligionRecognizer",
    "NlGpsRecognizer",
    "NlLicencePlateRecognizer",
    "NlUnknownNumberRecognizer",
]
