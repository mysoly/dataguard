"""careons_deid.core — low-level engine wrappers, data types, and base classes."""

from careons_deid.core.types import (
    AnalysisExplanation,
    OperatorConfig,
    Pattern,
    RecognizerResult,
)
from careons_deid.core.base_recognizer import EntityRecognizer, PatternRecognizer
from careons_deid.core.base_spacy import BaseSpacyRecognizer, InternalNlpArtifacts

__all__ = [
    "AnalysisExplanation",
    "OperatorConfig",
    "Pattern",
    "RecognizerResult",
    "EntityRecognizer",
    "PatternRecognizer",
    "BaseSpacyRecognizer",
    "InternalNlpArtifacts",
]
