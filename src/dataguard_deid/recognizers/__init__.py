"""
Recognizer registry for dataguard_deid.

Imports every domain recognizer and exports:
  - ALL_REGEX_RECOGNIZERS  – ordered list of recognizer *classes* (not instances)
    passed to GuardAnalyzer at engine initialisation.
  - Individual classes re-exported for direct import convenience.
"""

from dataguard_deid.recognizers.temporal import NlDateRecognizer, NlTimeRecognizer
from dataguard_deid.recognizers.contact import (
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlZipcodeRecognizer,
    NlUrlRecognizer,
)
from dataguard_deid.recognizers.identity import (
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlImeiRecognizer,
)
from dataguard_deid.recognizers.financial import (
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    NlCvvRecognizer,
    NlZorgpolisRecognizer,
    NlUnknownNumberRecognizer,
)
from dataguard_deid.recognizers.network import NlIpRecognizer, NlMacAddressRecognizer
from dataguard_deid.recognizers.medical import (
    NlGenderRecognizer,
    NlReligionRecognizer,
)
from dataguard_deid.recognizers.geo import NlGpsRecognizer, NlLicencePlateRecognizer
from dataguard_deid.recognizers.spacy_recognizer import NlNerRecognizer

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
    "NlReligionRecognizer",
    "NlGpsRecognizer",
    "NlLicencePlateRecognizer",
    "NlUnknownNumberRecognizer",
]
