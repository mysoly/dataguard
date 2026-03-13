"""Financial PII recognizers: IBAN_CODE, CREDIT_CARD, CVV, ZORGPOLIS_NUMBER, UNK_NUMBER."""
import re
from typing import List, Tuple

from dataguard_deid.core.base_recognizer import EntityRecognizer, PatternRecognizer
from dataguard_deid.core.types import RecognizerResult

from dataguard_deid.config.scoring import SCORE_PROFILES, RECOGNIZER_WINDOW_CHARS
from dataguard_deid.patterns.dutch_patterns import (
    IBAN_REGEX_NL,
    VISA_CREDIT_REGEX, MASTERCARD_REGEX,
    AMERICAN_EXPRESS_REGEX, DINERS_REGEX, DISCOVER_REGEX, JCB_REGEX,
    CVV_FULL_REGEX,
    ZORGPOLIS_NUMERIC, ZORGPOLIS_ALPHA, ZORGPOLIS_GROUPED,
    UNK_NUMBER_COMPACT, UNK_NUMBER_GROUPED,
)
from dataguard_deid.recognizers._helpers import _p
from dataguard_deid.recognizers._utils import luhn_check, validate_iban

_IB = SCORE_PROFILES["IBAN_CODE"]
_CC = SCORE_PROFILES["CREDIT_CARD"]
_CV = SCORE_PROFILES["CVV"]
_ZP = SCORE_PROFILES["ZORGPOLIS_NUMBER"]
_UK = SCORE_PROFILES["UNK_NUMBER"]


# ---------------------------------------------------------------------------
# IBAN — mod-97 validated
# ---------------------------------------------------------------------------

_IBAN_RE = re.compile(IBAN_REGEX_NL)


class NlIbanRecognizer(EntityRecognizer):
    """
    IBAN recognizer with ISO 13616 mod-97 checksum validation.
    Rejects structurally plausible but checksummed-invalid strings.
    """

    CONTEXT_WORDS = {
        "iban", "rekening", "bankrekeningnummer", "rekeningnummer",
        "bank", "bic", "swift", "giro", "gironummer", "betaalrekening",
    }

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    def __init__(self):
        super().__init__(supported_entities=["IBAN_CODE"], supported_language="nl")

    def load(self):
        pass

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "IBAN_CODE" not in entities:
            return []
        results = []
        for match in _IBAN_RE.finditer(text):
            raw = match.group(0)
            if not validate_iban(raw):
                continue
            lo = max(0, match.start() - self._WINDOW)
            hi = min(len(text), match.end() + self._WINDOW)
            window = text[lo:hi].lower()
            has_ctx = any(kw in window for kw in self.CONTEXT_WORDS)
            score = _IB.with_context if has_ctx else _IB.base
            results.append(
                RecognizerResult(
                    entity_type="IBAN_CODE",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                )
            )
        return results


# ---------------------------------------------------------------------------
# CREDIT CARD — Luhn-validated
# ---------------------------------------------------------------------------
#
# Luhn check outcome determines the emitted entity type:
#   passes  → CREDIT_CARD  (score = validated)
#   fails   → UNK_NUMBER   (score = base)
#
# Only network-specific patterns are evaluated; the former GENERAL_CREDITCARD
# catch-all is excluded to avoid excessive false positives.
#
# ---------------------------------------------------------------------------

_CC_SPECIFIC: List[Tuple[re.Pattern, str]] = [
    (re.compile(VISA_CREDIT_REGEX),        "Visa"),
    (re.compile(MASTERCARD_REGEX),         "Mastercard"),
    (re.compile(AMERICAN_EXPRESS_REGEX),   "Amex"),
    (re.compile(DINERS_REGEX),             "Diners"),
    (re.compile(DISCOVER_REGEX),           "Discover"),
    (re.compile(JCB_REGEX),                "JCB"),
]


class NlCreditCardRecognizer(EntityRecognizer):
    """
    Detects credit card numbers using network-specific regex patterns and
    validates each match with the Luhn algorithm.

    - Luhn-valid  → CREDIT_CARD
    - Luhn-invalid → UNK_NUMBER (something number-shaped but not a real card)
    """

    def __init__(self):
        super().__init__(
            supported_entities=["CREDIT_CARD", "UNK_NUMBER"],
            supported_language="nl",
        )

    def load(self):
        pass

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        results: List[RecognizerResult] = []
        covered: List[Tuple[int, int]] = []

        want_cc  = not entities or "CREDIT_CARD" in entities
        want_unk = not entities or "UNK_NUMBER"  in entities

        for pattern, _network in _CC_SPECIFIC:
            for match in pattern.finditer(text):
                ms, me = match.start(), match.end()
                if any(cs <= ms and me <= ce for cs, ce in covered):
                    continue

                digits = re.sub(r"[\s\-]", "", match.group(0))

                if luhn_check(digits):
                    if want_cc:
                        results.append(
                            RecognizerResult(
                                entity_type="CREDIT_CARD",
                                start=ms,
                                end=me,
                                score=_CC.validated,
                            )
                        )
                        covered.append((ms, me))
                else:
                    if want_unk:
                        results.append(
                            RecognizerResult(
                                entity_type="UNK_NUMBER",
                                start=ms,
                                end=me,
                                score=_UK.base,
                            )
                        )
                        covered.append((ms, me))

        return results


# ---------------------------------------------------------------------------
# CVV  (custom EntityRecognizer — only the digit group is the span)
# ---------------------------------------------------------------------------

_CVV_RE = re.compile(CVV_FULL_REGEX)


class NlCvvRecognizer(EntityRecognizer):
    """
    Detects CVV/CVC codes that follow a context keyword.
    Only the digit group is reported as the entity span so that
    the keyword itself (e.g. "CVV:") is preserved in the output.

    Score uses with_context because the regex itself already requires
    a preceding keyword — every match is by definition context-confirmed.
    """

    def __init__(self):
        super().__init__(supported_entities=["CVV"], supported_language="nl")

    def load(self):
        pass

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "CVV" not in entities:
            return []
        results = []
        for match in _CVV_RE.finditer(text):
            grp = 1 if match.group(1) is not None else 2
            results.append(
                RecognizerResult(
                    entity_type="CVV",
                    start=match.start(grp),
                    end=match.end(grp),
                    score=_CV.with_context,  # keyword already required by regex
                )
            )
        return results


# ---------------------------------------------------------------------------
# ZORGPOLIS  (four-tier scoring)
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
        high_confidence – explicit label keyword present   (beats BSN.validated)
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


# ---------------------------------------------------------------------------
# UNK_NUMBER catch-all
# ---------------------------------------------------------------------------
#
# Fires on any digit sequence not already claimed by a dedicated recognizer.
# The score (0.25) sits below every other entity's minimum base score, so
# resolve_overlaps always evicts an UNK_NUMBER result when a higher-confidence
# labelled entity covers the same span.
#
# Two complementary patterns:
#   compact – 4+ consecutive digits   (e.g. "156787", "0031701234567")
#   grouped – space-separated blocks  (e.g. "156 787", "12 34 56 78")
#
# ---------------------------------------------------------------------------


class NlUnknownNumberRecognizer(PatternRecognizer):
    """
    Catch-all recognizer that tags any digit sequence not already covered by a
    more specific recognizer as UNK_NUMBER.

    Because its score (0.25) is lower than every other entity's base score,
    resolve_overlaps will always prefer the labelled entity when spans overlap.
    """

    PATTERNS = [
        _p("unk_number_compact", UNK_NUMBER_COMPACT, _UK.base),
        _p("unk_number_grouped", UNK_NUMBER_GROUPED, _UK.base),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="UNK_NUMBER",
            patterns=self.PATTERNS,
            supported_language="nl",
        )
