"""
Rule-based context-awareness engine for post-processing PII detection scores.

Architecture
------------
Each ContextBoostRule describes *for a single entity type* how to decide whether
surrounding text supports the finding and, if so, how much to add to its score.

Two look-up strategies:
  match_in_span=True   – search the matched span itself for fuzzy vocabulary
                         (used for DATE: the span contains the month name)
  match_in_span=False  – search a character window around the span for exact
                         context keywords  (used for most other entity types)

Adding support for a new entity type requires only appending one or more
ContextBoostRule entries to CONTEXT_BOOST_RULES – no engine code changes.
"""

from __future__ import annotations

import difflib
import logging
from copy import copy
from dataclasses import dataclass, field
from typing import List, Optional

from dataguard_deid.types import AnalysisExplanation, RecognizerResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class ContextBoostRule:
    """
    Declarative rule that governs score boosting for one entity type.

    Attributes
    ----------
    entity_type     : entity label this rule applies to (e.g. "DATE")
    vocabulary      : exact substrings that, when found in the search area,
                      trigger the boost
    fuzzy_vocab     : reference words for fuzzy matching (SequenceMatcher)
    fuzzy_threshold : minimum similarity ratio to count as a fuzzy hit
    boost           : score delta to add; final score is capped at 1.0
    only_if_below   : skip entities whose current score already exceeds this
                      value — avoids double-boosting high-confidence results
    match_in_span   : True  → search inside the matched span
                      False → search in a character window around the span
    window          : half-window size in characters (only when match_in_span=False)
    """
    entity_type: str
    vocabulary: List[str] = field(default_factory=list)
    fuzzy_vocab: List[str] = field(default_factory=list)
    fuzzy_threshold: float = 0.80
    boost: float = 0.35
    only_if_below: Optional[float] = None
    match_in_span: bool = True
    window: int = 80


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

CONTEXT_BOOST_RULES: List[ContextBoostRule] = [

    # ── DATE ─────────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="DATE",
        fuzzy_vocab=[
            "januari", "jan", "februari", "feb", "maart", "mar",
            "april", "apr", "mei", "juni", "jun", "juli", "jul",
            "augustus", "aug", "september", "sep", "oktober", "okt",
            "november", "nov", "december", "dec",
        ],
        fuzzy_threshold=0.75,
        boost=0.45,
        only_if_below=0.50,
        match_in_span=True,
    ),

    # ── TIME ─────────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="TIME",
        vocabulary=["uur", "tijd", "om", "tijdstip", "aanvang", "eindtijd", "klokslag", "minuut"],
        boost=0.25,
        only_if_below=0.60,
        match_in_span=False,
        window=60,
    ),

    # ── PHONE_NUMBER ─────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="PHONE_NUMBER",
        vocabulary=[
            "telefoon", "tel", "mobiel", "gsm", "06", "bel",
            "whatsapp", "contactnummer", "telefoonnummer", "werktelefoon",
        ],
        boost=0.30,
        only_if_below=0.50,
        match_in_span=False,
        window=80,
    ),

    # ── ZIPCODE ──────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="ZIPCODE",
        vocabulary=["postcode", "adres", "woonplaats", "postadres", "straat", "huisnummer"],
        boost=0.20,
        only_if_below=0.70,
        match_in_span=False,
        window=80,
    ),

    # ── GPS_COORDINATES ──────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="GPS_COORDINATES",
        vocabulary=[
            "gps", "coördinaten", "coordinates", "locatie", "location",
            "lat", "lon", "latitude", "longitude",
            "lengtegraad", "breedtegraad", "positie", "kaart",
        ],
        boost=0.25,
        only_if_below=0.80,
        match_in_span=False,
        window=80,
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DutchContextEnhancer:
    """
    Iterates over a list of RecognizerResults and applies every matching
    ContextBoostRule to raise the score of uncertain findings.

    Custom rules can be injected at construction time; the default set is
    CONTEXT_BOOST_RULES defined above.
    """

    def __init__(self, rules: Optional[List[ContextBoostRule]] = None) -> None:
        self._rules_by_type: dict[str, list[ContextBoostRule]] = {}
        for rule in rules or CONTEXT_BOOST_RULES:
            self._rules_by_type.setdefault(rule.entity_type, []).append(rule)

    def enhance(
        self, text: str, results: List[RecognizerResult]
    ) -> List[RecognizerResult]:
        """
        Apply all matching boost rules to *results* and return the updated list.
        Each result that receives a boost is shallow-copied before modification
        so the original RecognizerResult objects from the analyzer are never mutated.
        """
        text_lower = text.lower()
        output: List[RecognizerResult] = []
        for res in results:
            matching_rules = [
                rule
                for rule in self._rules_by_type.get(res.entity_type, [])
                if not (rule.only_if_below is not None and res.score >= rule.only_if_below)
                and self._matches(text_lower, res, rule)
            ]
            if matching_rules:
                res = copy(res)
                for rule in matching_rules:
                    self._boost(res, rule)
            output.append(res)
        return output

    def _matches(
        self, text_lower: str, res: RecognizerResult, rule: ContextBoostRule
    ) -> bool:
        if rule.match_in_span:
            search = text_lower[res.start : res.end]
        else:
            lo = max(0, res.start - rule.window)
            hi = min(len(text_lower), res.end + rule.window)
            search = text_lower[lo:hi]

        if any(kw in search for kw in rule.vocabulary):
            return True

        if rule.fuzzy_vocab:
            words = "".join(c if c.isalpha() else " " for c in search).split()
            for word in words:
                if len(word) < 3:
                    continue
                best_ratio = max(
                    (difflib.SequenceMatcher(None, word, ref).ratio() for ref in rule.fuzzy_vocab),
                    default=0.0,
                )
                if best_ratio >= rule.fuzzy_threshold:
                    logger.debug(
                        "ContextBoostRule(%s): fuzzy hit ratio=%.2f",
                        rule.entity_type,
                        best_ratio,
                    )
                    return True
        return False

    @staticmethod
    def _boost(res: RecognizerResult, rule: ContextBoostRule) -> None:
        old = res.score
        res.score = min(1.0, old + rule.boost)

        expl = res.analysis_explanation
        if expl is None:
            expl = AnalysisExplanation(
                recognizer="DutchContextEnhancer",
                original_score=old,
            )
            res.analysis_explanation = expl

        expl.append_textual_explanation_line(
            f"ContextBoostRule({rule.entity_type}): "
            f"{old:.2f} → {res.score:.2f} (+{rule.boost})"
        )
