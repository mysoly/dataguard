"""IDENTIFIER group recognizers: BSN, PASSPORT, ZORGPOLIS_NUMBER."""
import re
from typing import List

from dataguard_deid.recognizers.base import EntityRecognizer, PatternRecognizer
from dataguard_deid.types import AnalysisExplanation, RecognizerResult

from dataguard_deid.config.scoring import SCORE_PROFILES, RECOGNIZER_WINDOW_CHARS
from dataguard_deid.patterns.dutch_patterns import (
    BSN_REGEX_NL, PASSPORT_LICENCE_NL,
    ZORGPOLIS_NUMERIC, ZORGPOLIS_ALPHA, ZORGPOLIS_GROUPED,
)
from dataguard_deid.recognizers._helpers import _p

_BS = SCORE_PROFILES["BSN"]
_PA = SCORE_PROFILES["PASSPORT"]
_ZP = SCORE_PROFILES["ZORGPOLIS_NUMBER"]


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
    """

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    _POSITIVE_CONTEXT = {
        "bsn", "burgerservicenummer", "sofinummer", "sofi",
        "persoonsnummer", "fiscaal nummer", "identificatienummer",
        "id-nummer", "digid",
    }

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
# ZORGPOLIS_NUMBER — four-tier scoring
# ---------------------------------------------------------------------------

_ZORGPOLIS_STRONG_CONTEXT = {
    "zorgpolisnummer", "polisnummer", "verzekeringsnummer", "polisnr",
}
_ZORGPOLIS_WEAK_CONTEXT = {
    "zorgpolis", "zorgverzekering", "verzekeringspolis",
}
_ZORGPOLIS_INSURER_NAMES = {
    "vgz", "cz", "zilveren kruis", "menzis", "dsw", "onvz",
}

_ZORGPOLIS_PATTERNS = [
    re.compile(ZORGPOLIS_GROUPED),
    re.compile(ZORGPOLIS_ALPHA),
    re.compile(ZORGPOLIS_NUMERIC),
]


class NlZorgpolisRecognizer(EntityRecognizer):
    """
    Detects Dutch health insurance policy numbers (Zorgpolisnummer).

    Score tier mapping:
        high_confidence – explicit label keyword present
        validated       – weak context + insurer name
        with_context    – weak context keyword only
        base            – regex only, no context
    """

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    def __init__(self):
        super().__init__(supported_entities=["ZORGPOLIS_NUMBER"], supported_language="nl")

    def load(self):
        pass

    def _context_window(self, text: str, start: int, end: int) -> str:
        lo = max(0, start - self._WINDOW)
        hi = min(len(text), end + self._WINDOW)
        return text[lo:hi].lower()

    @staticmethod
    def _pattern_base(pattern_index: int) -> float:
        if pattern_index == 0:
            return 0.40
        elif pattern_index == 1:
            return 0.10
        else:
            return _ZP.base

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "ZORGPOLIS_NUMBER" not in entities:
            return []
        results: List[RecognizerResult] = []
        covered: List[tuple] = []

        for pat_idx, pattern in enumerate(_ZORGPOLIS_PATTERNS):
            for match in pattern.finditer(text):
                ms, me = match.start(), match.end()
                if any(cs <= ms and me <= ce for cs, ce in covered):
                    continue

                window = self._context_window(text, ms, me)
                has_strong  = any(kw in window for kw in _ZORGPOLIS_STRONG_CONTEXT)
                has_weak    = any(kw in window for kw in _ZORGPOLIS_WEAK_CONTEXT)
                has_insurer = any(ins in window for ins in _ZORGPOLIS_INSURER_NAMES)

                if has_strong:
                    score = _ZP.high_confidence
                elif has_weak and has_insurer:
                    score = _ZP.validated
                elif has_weak:
                    score = _ZP.with_context
                else:
                    score = self._pattern_base(pat_idx)

                results.append(
                    RecognizerResult(
                        entity_type="ZORGPOLIS_NUMBER",
                        start=ms,
                        end=me,
                        score=score,
                    )
                )
                covered.append((ms, me))

        return results
