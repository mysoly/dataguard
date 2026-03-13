"""
GuardEngine — text anonymization engine.  Zero external dependencies.

Modes
-----
anonymize : replace each PII span with a realistic synthetic Dutch value
tag       : replace with [ENTITY_TYPE] bracket labels (e.g. [PERSON])
i_tag     : replace with [ENTITY_TYPE_INDEX] labels  (e.g. [PERSON_1])
"""

import logging
from itertools import cycle
from typing import Dict, List, Optional

from dataguard_deid.anonymization.fake_data import FakeDataProvider
from dataguard_deid.config.entities import ALL_NL_ENTITY_TYPES

logger = logging.getLogger(__name__)

_VALID_MODES = frozenset({"anonymize", "tag", "i_tag"})

# Entity types that get their own bracket label; anything else → [PII].
_KNOWN_ENTITIES = frozenset(ALL_NL_ENTITY_TYPES)


# ---------------------------------------------------------------------------
# Internal replacement helpers
# ---------------------------------------------------------------------------

def _apply_fake_guard(
    text: str,
    analyzer_results: list,
    anonymize_list: Optional[Dict[str, List[str]]] = None,
) -> str:
    """
    Replace each detected span with a realistic synthetic Dutch value.

    Processes spans right-to-left so offsets stay valid after each replacement.
    Within one call, the same original value always maps to the same fake.
    """
    provider = FakeDataProvider()

    if anonymize_list:
        for entity_name, values in anonymize_list.items():
            if values:
                provider._cycles[entity_name] = cycle(values)

    for result in sorted(analyzer_results, key=lambda r: r.start, reverse=True):
        original = text[result.start: result.end]
        fake = provider.get(result.entity_type, original)
        text = text[: result.start] + fake + text[result.end:]

    return text


def _apply_tag_guard(
    text: str,
    analyzer_results: list,
    extra_entities: Optional[List[str]] = None,
    label_mapping: Optional[Dict[str, str]] = None,
) -> str:
    """
    Replace each detected span with a bracket label.

    When *label_mapping* is provided the display label is resolved via the
    mapping (grouped mode); otherwise the entity_type is used directly.
    Known entity types fall back to ``[PII]`` only when no mapping is active.
    """
    known = _KNOWN_ENTITIES | set(extra_entities or [])

    for result in sorted(analyzer_results, key=lambda r: r.start, reverse=True):
        if label_mapping:
            display = label_mapping.get(result.entity_type, result.entity_type)
        else:
            display = result.entity_type if result.entity_type in known else "PII"
        text = text[: result.start] + f"[{display}]" + text[result.end:]

    return text


def _apply_indexed_tagging(
    text: str,
    analyzer_results: list,
    label_mapping: Optional[Dict[str, str]] = None,
) -> str:
    """
    Replace each detected span with an indexed label tag ``[LABEL_N]``.

    When *label_mapping* is provided, counters and deduplication are keyed on
    the group label so that DATE_1 and TIME_1 merge into DATETIME_1.
    """
    counters: Dict[str, int] = {}
    seen_map: Dict[tuple, int] = {}
    indexed_findings = []

    for result in sorted(analyzer_results, key=lambda r: r.start):
        original = text[result.start: result.end]
        display = (
            label_mapping.get(result.entity_type, result.entity_type)
            if label_mapping else result.entity_type
        )
        key = (display, original)

        if key not in seen_map:
            existing_idx = None
            if display == "PERSON":
                for (etype, old_text), idx in list(seen_map.items()):
                    if etype == "PERSON" and (original in old_text or old_text in original):
                        existing_idx = idx
                        break

            if existing_idx is not None:
                seen_map[key] = existing_idx
            else:
                counters[display] = counters.get(display, 0) + 1
                seen_map[key] = counters[display]

        tag = f"[{display}_{seen_map[key]}]"
        indexed_findings.append((result.start, result.end, tag))

    for start, end, tag in sorted(indexed_findings, key=lambda x: x[0], reverse=True):
        text = text[:start] + tag + text[end:]

    return text


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class GuardEngine:
    """
    Stateless anonymization dispatcher.

    All state (spaCy model, recognizers) lives in GuardAnalyzer.  GuardEngine
    performs only string operations and therefore requires no singleton or lock.
    """

    @classmethod
    def guard(
        cls,
        text: str,
        analyzer_results: list,
        mode: str = "anonymize",
        extra_entities: Optional[List[str]] = None,
        anonymize_list: Optional[Dict[str, List[str]]] = None,
        label_mapping: Optional[Dict[str, str]] = None,
    ) -> Dict:
        """
        Process the analyzer findings and guard the text.

        :param text:             Original input string.
        :param analyzer_results: List of RecognizerResult from GuardAnalyzer.
        :param mode:             "anonymize" (default), "tag", or "i_tag".
        :param extra_entities:   Entity-type names from custom patterns. In tag
            mode each gets its own ``[NAME]`` label instead of ``[PII]``.
        :param anonymize_list:   Supplemental fake-value pools for custom entity
            types, e.g. ``{"MEDICATION": ["Aspirine", "Ibuprofen"]}``.
            Only used in ``anonymize`` mode.
        :param label_mapping:    Optional sub_label → group_label dict. When
            provided, tag/i_tag modes use group labels and ``"type"`` in findings
            reflects the group label.
        :returns: ``{"guarded_text": str, "findings": list}``
        """
        if mode not in _VALID_MODES:
            raise ValueError(
                f"Unknown guard mode {mode!r}. "
                f"Choose from: {sorted(_VALID_MODES)}"
            )

        findings = [
            {
                "type": label_mapping.get(r.entity_type, r.entity_type) if label_mapping else r.entity_type,
                "start": r.start,
                "end": r.end,
                "score": round(r.score, 4),
                "original_text": text[r.start: r.end],
            }
            for r in analyzer_results
        ]

        if mode == "anonymize":
            output_text = _apply_fake_guard(
                text, analyzer_results, anonymize_list=anonymize_list
            )
        elif mode == "i_tag":
            output_text = _apply_indexed_tagging(
                text, analyzer_results, label_mapping=label_mapping
            )
        else:  # tag
            output_text = _apply_tag_guard(
                text, analyzer_results,
                extra_entities=extra_entities,
                label_mapping=label_mapping,
            )

        logger.info(
            "Guarded text (%d chars, %d findings, mode=%s)",
            len(text), len(findings), mode,
        )
        return {
            "guarded_text": output_text,
            "findings": findings,
        }
