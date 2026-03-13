"""
BaseSpacyRecognizer — base class for spaCy NER-based PII recognizers.

Architecture
------------
GuardAnalyzer runs the spaCy pipeline and maps the raw Dutch NER labels to
canonical names using _DUTCH_NER_MAPPING before building InternalNlpArtifacts:

  spaCy doc.ents  →  _MappedSpan wrapper  →  InternalNlpArtifacts.entities
     PER                  NER mapping              PERSON
     LOC                                           LOCATION
     GPE                                           LOCATION
     ...                                           ...

By the time InternalNlpArtifacts reaches a recognizer, all entity labels are
already canonical names.  BaseSpacyRecognizer therefore only needs to:

  1. Iterate nlp_artifacts.entities + nlp_artifacts.scores.
  2. Filter by supported_entities and the requested entity list.
  3. Build RecognizerResult objects using dataguard_deid.core.types.

InternalNlpArtifacts is defined in this module so that guard_analyzer.py can
import it without a circular dependency.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from dataguard_deid.core.base_recognizer import EntityRecognizer
from dataguard_deid.core.types import AnalysisExplanation, RecognizerResult

logger = logging.getLogger("dataguard-deid")


# ---------------------------------------------------------------------------
# InternalNlpArtifacts
# ---------------------------------------------------------------------------

class InternalNlpArtifacts:
    """
    Lightweight NLP artifacts container consumed by BaseSpacyRecognizer.

    GuardAnalyzer builds one of these per request from the spaCy Doc, using
    _MappedSpan wrappers so that label remapping is transparent to the
    recognizer layer.

    :param entities: List of span-like objects exposing ``.label_``,
        ``.start_char``, and ``.end_char``.
    :param scores: Per-entity confidence scores (same length as entities).
    """

    __slots__ = ("entities", "scores")

    def __init__(self, entities: list, scores: List[float]):
        self.entities = entities
        self.scores = scores


class BaseSpacyRecognizer(EntityRecognizer):
    """
    Abstract base class for spaCy NER-based PII recognizers.

    Subclasses declare which entity labels they support and may override
    ``analyze()`` to add post-processing (e.g. false-positive filtering).

    GuardAnalyzer remaps raw Dutch spaCy labels to canonical names before
    building InternalNlpArtifacts, so subclasses receive ready-to-use labels
    (e.g. "PERSON", "LOCATION") without needing their own mapping.

    :param supported_entities: Canonical entity type labels to detect.
    :param ner_strength: Default confidence score (default 0.85).  Used
        when NlpArtifacts does not supply per-entity scores.
    :param supported_language: ISO-639-1 language code (default "nl").
    :param name: Optional recognizer name (defaults to class name).
    :param version: Recognizer version string.
    """

    DEFAULT_EXPLANATION = (
        "Identified as {} by spaCy Named Entity Recognition"
    )

    def __init__(
        self,
        supported_entities: List[str],
        ner_strength: float = 0.85,
        supported_language: str = "nl",
        name: Optional[str] = None,
        version: str = "0.0.1",
    ):
        self.ner_strength = ner_strength
        super().__init__(
            supported_entities=supported_entities,
            name=name,
            supported_language=supported_language,
            version=version,
        )

    def load(self) -> None:  # noqa: D102
        # No assets to load; the spaCy model is managed by the NLP engine.
        pass

    def build_explanation(
        self,
        original_score: float,
        explanation_text: str,
    ) -> AnalysisExplanation:
        """Build an AnalysisExplanation for a NER detection."""
        return AnalysisExplanation(
            recognizer=self.name,
            original_score=original_score,
            textual_explanation=explanation_text,
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None,
    ) -> List[RecognizerResult]:
        """
        Extract NER entities from *nlp_artifacts* and return RecognizerResults.

        Entities in nlp_artifacts have already been remapped to canonical
        labels (e.g. PER→PERSON) by GuardAnalyzer before this method is called.

        :param text: The original text (used for building result objects).
        :param entities: Entity types requested for this analysis pass.
        :param nlp_artifacts: InternalNlpArtifacts produced by GuardAnalyzer.
            If None, an empty list is returned.
        :return: List of RecognizerResult.
        """
        if not nlp_artifacts:
            logger.warning(
                "Skipping %s — nlp_artifacts not provided.", self.name
            )
            return []

        results: List[RecognizerResult] = []

        for ner_entity, ner_score in zip(
            nlp_artifacts.entities, nlp_artifacts.scores
        ):
            entity_label = ner_entity.label_

            if entity_label not in self.supported_entities:
                continue
            if entities and entity_label not in entities:
                continue

            explanation_text = self.DEFAULT_EXPLANATION.format(entity_label)
            explanation = self.build_explanation(ner_score, explanation_text)

            result = RecognizerResult(
                entity_type=entity_label,
                start=ner_entity.start_char,
                end=ner_entity.end_char,
                score=ner_score,
                analysis_explanation=explanation,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                },
            )
            results.append(result)

        return results
