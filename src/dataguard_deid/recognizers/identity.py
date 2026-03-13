"""Identity-document PII recognizers: BSN, PASSPORT, IMEI."""
import re
from typing import List

from dataguard_deid.core.base_recognizer import EntityRecognizer, PatternRecognizer
from dataguard_deid.core.types import AnalysisExplanation, RecognizerResult

from dataguard_deid.config.scoring import SCORE_PROFILES, RECOGNIZER_WINDOW_CHARS
from dataguard_deid.patterns.dutch_patterns import BSN_REGEX_NL, IMEI_REGEX, PASSPORT_LICENCE_NL
from dataguard_deid.recognizers._helpers import _p
from dataguard_deid.recognizers._utils import luhn_check

_BS = SCORE_PROFILES["BSN"]
_PA = SCORE_PROFILES["PASSPORT"]
_IM = SCORE_PROFILES["IMEI"]


# ---------------------------------------------------------------------------
# BSN — 11-proef (elfproef) validation
# ---------------------------------------------------------------------------

class NlBsnRecognizer(EntityRecognizer):
    """
    BSN recognizer with elfproef (11-proef) checksum validation.

    Scoring tiers
    -------------
    high_confidence  – checksum passes AND a BSN-specific keyword is nearby
    validated        – checksum passes, no keyword context (default)
    base             – checksum passes BUT a competing-entity keyword is nearby
                       (negative context: reduces score so the other entity wins
                       in overlap resolution)

    Note on CONTEXT
    ---------------
    Positive-context boosting is implemented manually in _score_for_match()
    by inspecting the surrounding character window.
    """

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    # Keywords that confirm a 9-digit number IS a BSN.
    _POSITIVE_CONTEXT = {
        "bsn", "burgerservicenummer", "sofinummer", "sofi",
        "persoonsnummer", "fiscaal nummer", "identificatienummer",
        "id-nummer", "digid",
    }

    # Keywords that indicate the number is NOT a BSN.
    _NEGATIVE_CONTEXT = {
        "zorgpolisnummer", "polisnummer", "verzekeringsnummer", "polisnr",
        "zorgpolis", "zorgverzekering", "verzekeringspolis",
        "klantnummer", "ordernummer", "factuurnummer",
    }

    def __init__(self):
        super().__init__(supported_entities=["BSN"], supported_language="nl")

    def load(self):
        pass

    @staticmethod
    def _is_valid_bsn(bsn_str: str) -> bool:
        if bsn_str == "000000000":
            return False
        weights = [9, 8, 7, 6, 5, 4, 3, 2, -1]
        return sum(int(d) * w for d, w in zip(bsn_str, weights)) % 11 == 0

    def _window_lower(self, text: str, start: int, end: int) -> str:
        lo = max(0, start - self._WINDOW)
        hi = min(len(text), end + self._WINDOW)
        return text[lo:hi].lower()

    def _score_for_match(self, text: str, start: int, end: int) -> float:
        window = self._window_lower(text, start, end)
        if any(kw in window for kw in self._NEGATIVE_CONTEXT):
            return _BS.base
        if any(kw in window for kw in self._POSITIVE_CONTEXT):
            return _BS.high_confidence
        return _BS.validated

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "BSN" not in entities:
            return []
        results = []
        for match in re.finditer(BSN_REGEX_NL, text):
            if not self._is_valid_bsn(match.group(0)):
                continue
            score = self._score_for_match(text, match.start(), match.end())
            results.append(
                RecognizerResult(
                    entity_type="BSN",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    analysis_explanation=AnalysisExplanation(
                        recognizer=self.__class__.__name__,
                        original_score=score,
                        pattern_name="bsn_9digit_elfproef",
                        pattern=BSN_REGEX_NL,
                        validation_result=True,
                    ),
                )
            )
        return results


# ---------------------------------------------------------------------------
# PASSPORT / DRIVING LICENSE
# ---------------------------------------------------------------------------

class NlPassportRecognizer(PatternRecognizer):
    PATTERNS = [_p("passport_nl", PASSPORT_LICENCE_NL, _PA.base)]
    CONTEXT = [
        "paspoort", "passport", "rijbewijs", "documentnummer",
        "paspoortnummer", "paspoortnr", "rijbewijsnr",
        "id-kaart", "identiteitsbewijs", "identiteitskaart",
        "reisdocument", "pas",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PASSPORT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


# ---------------------------------------------------------------------------
# IMEI — Luhn checksum validation
# ---------------------------------------------------------------------------

class NlImeiRecognizer(EntityRecognizer):
    """
    IMEI recognizer with Luhn checksum validation.

    Context boosting is applied manually in analyze() by inspecting the
    surrounding character window.
    """

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    _POSITIVE_CONTEXT = {
        "imei", "apparaat", "device", "telefoon", "serienummer",
        "sim", "telefoonidentiteit", "imei-nummer",
    }

    def __init__(self):
        super().__init__(supported_entities=["IMEI"], supported_language="nl")

    def load(self):
        pass

    def _window_lower(self, text: str, start: int, end: int) -> str:
        lo = max(0, start - self._WINDOW)
        hi = min(len(text), end + self._WINDOW)
        return text[lo:hi].lower()

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "IMEI" not in entities:
            return []
        results = []
        for match in re.finditer(IMEI_REGEX, text):
            if not luhn_check(match.group(0)):
                continue
            window = self._window_lower(text, match.start(), match.end())
            score = (
                _IM.high_confidence
                if any(kw in window for kw in self._POSITIVE_CONTEXT)
                else _IM.validated
            )
            results.append(
                RecognizerResult(
                    entity_type="IMEI",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    analysis_explanation=AnalysisExplanation(
                        recognizer=self.__class__.__name__,
                        original_score=score,
                        pattern_name="imei_15digit_luhn",
                        pattern=IMEI_REGEX,
                        validation_result=True,
                    ),
                )
            )
        return results
