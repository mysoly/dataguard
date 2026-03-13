"""
dataguard_deid

A standalone Python library for detecting and anonymizing Dutch PII.
Powered by a custom NLP engine and spaCy.

Package layout
--------------
dataguard_deid/
├── core/
│   ├── types.py          — internal data structures (RecognizerResult, Pattern, …)
│   ├── base_recognizer.py — EntityRecognizer / PatternRecognizer base classes
│   ├── base_spacy.py     — spaCy NER base class
│   ├── analyzer.py       — analysis engine wrapper + entity resolution
│   └── guard.py          — guard engine wrapper
└── processors/
    ├── text_processor.py — analyze / guard pipelines for plain-text input
    └── doc_processor.py  — file reading (.pdf/.docx/.txt) + text pipelines

Public interface::

    from dataguard_deid import analyze, guard, custom_pattern

    analyze.text("Jan de Vries woont in Amsterdam.")
    analyze.doc("/path/to/report.pdf")

    guard.text("Jan de Vries woont in Amsterdam.")
    guard.doc("/path/to/rapport.docx")

    pattern = custom_pattern(name="EMPLOYEE_ID", regex=r"EMP-\\d{4}")
    guard.text(text, config={"custom_patterns": [pattern]})
"""

import types
from typing import Any, Dict, List, Optional

__version__ = "1.2.0"

from dataguard_deid.processors.text_processor import analyze as _analyze, guard as _guard
from dataguard_deid.processors.doc_processor import (
    analyze as _analyze_doc,
    guard as _guard_doc,
)

# ---------------------------------------------------------------------------
# Public namespace objects
# ---------------------------------------------------------------------------

analyze = types.SimpleNamespace(
    text=_analyze,
    doc=_analyze_doc,
)

guard = types.SimpleNamespace(
    text=_guard,
    doc=_guard_doc,
)


def custom_pattern(
    name: str,
    regex: str,
    score: float = 0.85,
    context: Optional[List[str]] = None,
    anonymize_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build a custom pattern definition for use in ``config["custom_patterns"]``.

    Args:
        name           : Entity type label (e.g. ``"EMPLOYEE_ID"``).
        regex          : Python regex string.
        score          : Confidence score (default 0.85).
        context        : Words near the match that boost confidence.
        anonymize_list : Fake replacement values for anonymize mode.

    Returns:
        dict ready for ``config["custom_patterns"]``.

    Example::

        from dataguard_deid import guard, custom_pattern

        pattern = custom_pattern(
            name="EMPLOYEE_ID",
            regex=r"EMP-\\d{4}",
            score=0.9,
            context=["medewerker", "employee"],
            anonymize_list=["EMP-0001", "EMP-0002"],
        )
        guard.text(text, config={"custom_patterns": [pattern]})
        guard.doc("/path/to/file.pdf", config={"custom_patterns": [pattern]})
    """
    return {
        "name": name,
        "regex": regex,
        "score": score,
        "context": context,
        "anonymize_list": anonymize_list,
    }


from dataguard_deid.config.entities import ALL_NL_ENTITY_TYPES
from dataguard_deid.processors.doc_processor import UnsupportedFormatError

__all__ = [
    "analyze",
    "guard",
    "custom_pattern",
    "ALL_NL_ENTITY_TYPES",
    "UnsupportedFormatError",
    "__version__",
]
