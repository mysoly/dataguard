"""
careons_deid.core.guard
----------------------
Thin wrapper around the GuardEngine.

Responsibilities
~~~~~~~~~~~~~~~~
- Accepting pre-computed RecognizerResult objects (from core.analyzer)
- Dispatching to GuardEngine with the selected mode
- Returning the raw result dict produced by GuardEngine

Upper layers (processors/) are responsible for all config parsing and
formatting before calling into this module.
"""

from typing import Dict, List, Optional

from careons_deid.guard_engine.guard_engine import GuardEngine


def run(
    text: str,
    analyzer_results: List,
    mode: str = "anonymize",
    extra_entities: Optional[List[str]] = None,
    anonymize_list: Optional[Dict[str, List[str]]] = None,
) -> Dict:
    """
    Apply a guard strategy to *text* using pre-computed analysis results.

    Parameters
    ----------
    text             : The original Dutch text.
    analyzer_results : ``RecognizerResult`` list from ``core.analyzer.run``.
    mode             : ``"anonymize"`` | ``"tag"`` | ``"i_tag"``
    extra_entities   : Custom entity-type names for correct tag-mode labelling.
    anonymize_list   : Per-entity fake-value pools for anonymize mode.

    Returns
    -------
    dict
        ``guarded_text`` – processed text with PII replaced.
        ``findings``     – list of finding dicts (type, start, end, score).
    """
    return GuardEngine.guard(
        text=text,
        analyzer_results=analyzer_results,
        mode=mode,
        extra_entities=extra_entities,
        anonymize_list=anonymize_list,
    )
