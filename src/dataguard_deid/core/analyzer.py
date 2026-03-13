"""
dataguard_deid.core.analyzer
-------------------------
Thin wrapper around the GuardAnalyzer engine.

Responsibilities
~~~~~~~~~~~~~~~~
- Entity-list resolution (keep / ignore filtering + custom pattern names)
- Dispatching to GuardAnalyzer and returning raw RecognizerResult objects

Upper layers (processors/) consume this module; nothing here knows about
config dicts, file paths, or output formatting.
"""

from typing import Any, Dict, List, Optional

from dataguard_deid.guard_engine.guard_analyzer import GuardAnalyzer
from dataguard_deid.config.entities import ALL_NL_ENTITY_TYPES


def resolve_entities(
    set_entities: Optional[Dict],
    custom_patterns: Optional[List[Dict]] = None,
) -> Optional[List[str]]:
    """
    Resolve the entity filter from a ``set_entities`` config block.

    Parameters
    ----------
    set_entities : dict or None
        ``{"keep": [...]}``  – allowlist: only these types are scanned.
        ``{"ignore": [...]}`` – denylist: these types are skipped.
        ``None``              – no filter; scan everything.
    custom_patterns : list of dicts, optional
        Custom pattern definitions whose ``name`` keys may appear in ``keep``.

    Returns
    -------
    list[str] or None
        Resolved entity list, or ``None`` if no filtering is required.
    """
    if not set_entities:
        return None

    keep = set_entities.get("keep")
    ignore = set_entities.get("ignore")
    custom_names: List[str] = [p["name"] for p in (custom_patterns or []) if "name" in p]

    if keep is not None:
        if not keep:
            return []
        built_in = [e for e in ALL_NL_ENTITY_TYPES if e in keep]
        extras = [e for e in keep if e not in ALL_NL_ENTITY_TYPES and e in custom_names]
        return built_in + extras

    if ignore is not None:
        built_in = [e for e in ALL_NL_ENTITY_TYPES if e not in ignore]
        extras = [e for e in custom_names if e not in ignore and e not in built_in]
        return built_in + extras

    return None


def run(
    text: str,
    entities: Optional[List[str]] = None,
    score_threshold: float = 0.0,
    custom_patterns: Optional[List[Dict[str, Any]]] = None,
) -> List:
    """
    Run PII detection on *text* and return raw ``RecognizerResult`` objects.

    Parameters
    ----------
    text             : Dutch text to analyse.
    entities         : Explicit entity-type list (``None`` = scan all).
    score_threshold  : Minimum score; results below this are dropped.
    custom_patterns  : Additional user-defined regex patterns.

    Returns
    -------
    list[RecognizerResult]
    """
    engine = GuardAnalyzer()
    return engine.analyze(
        text,
        entities=entities,
        score_threshold=score_threshold,
        custom_patterns=custom_patterns,
    )
