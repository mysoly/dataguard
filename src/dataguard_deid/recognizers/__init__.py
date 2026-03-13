"""
Recognizer registry for dataguard_deid.

Imports every domain recognizer and exports:
  - ALL_REGEX_RECOGNIZERS  – ordered list of recognizer *classes* (not instances)
    passed to GuardAnalyzer at engine initialisation.
  - Individual classes re-exported for direct import convenience.
"""

from dataguard_deid.recognizers.datetime import NlDateRecognizer, NlTimeRecognizer
from dataguard_deid.recognizers.contact import (
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlUrlRecognizer,
)
from dataguard_deid.recognizers.location import NlZipcodeRecognizer, NlGpsRecognizer
from dataguard_deid.recognizers.identifier import (
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlZorgpolisRecognizer,
)
from dataguard_deid.recognizers.financial import (
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    NlCvvRecognizer,
)
from dataguard_deid.recognizers.device import (
    NlIpRecognizer,
    NlMacAddressRecognizer,
    NlImeiRecognizer,
)
from dataguard_deid.recognizers.vehicle import NlLicencePlateRecognizer
from dataguard_deid.recognizers.spacy_recognizer import NlNerRecognizer

ALL_REGEX_RECOGNIZERS = [
    # ── DATETIME ─────────────────────────────────────────────────
    NlDateRecognizer,
    NlTimeRecognizer,
    # ── CONTACT ──────────────────────────────────────────────────
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlUrlRecognizer,
    # ── LOCATION ─────────────────────────────────────────────────
    NlZipcodeRecognizer,
    NlGpsRecognizer,
    # ── IDENTIFIER ───────────────────────────────────────────────
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlZorgpolisRecognizer,
    # ── FINANCIAL ────────────────────────────────────────────────
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    NlCvvRecognizer,
    # ── DEVICE_IDENTIFIER ────────────────────────────────────────
    NlIpRecognizer,
    NlMacAddressRecognizer,
    NlImeiRecognizer,
    # ── VEHICLE_IDENTIFIER ───────────────────────────────────────
    NlLicencePlateRecognizer,
]

__all__ = [
    "ALL_REGEX_RECOGNIZERS",
    "NlNerRecognizer",
    "NlDateRecognizer",
    "NlTimeRecognizer",
    "NlPhoneRecognizer",
    "NlEmailRecognizer",
    "NlUrlRecognizer",
    "NlZipcodeRecognizer",
    "NlGpsRecognizer",
    "NlBsnRecognizer",
    "NlPassportRecognizer",
    "NlZorgpolisRecognizer",
    "NlIbanRecognizer",
    "NlCreditCardRecognizer",
    "NlCvvRecognizer",
    "NlIpRecognizer",
    "NlMacAddressRecognizer",
    "NlImeiRecognizer",
    "NlLicencePlateRecognizer",
]
