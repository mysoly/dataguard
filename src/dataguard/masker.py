import re
from typing import Optional

PATTERNS: dict[str, str] = {
    "email": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "credit_card": r"\b(?:\d[ \-]?){13,15}\d\b",
    "phone": r"\+?[\d\s\-().]{7,20}",
    "ssn": r"\b\d{3}[- ]\d{2}[- ]\d{4}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "iban": r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b",
}


def mask(
    text: str,
    patterns: Optional[list[str]] = None,
    placeholder: str = "[REDACTED]",
    custom_patterns: Optional[dict[str, str]] = None,
) -> str:
    """Mask sensitive data in *text* using regex patterns.

    Args:
        text: Input string to process.
        patterns: Names of built-in patterns to apply. Defaults to all built-ins.
        placeholder: Replacement string for matched values.
        custom_patterns: Extra ``{name: regex}`` patterns to apply.

    Returns:
        String with matched values replaced by *placeholder*.
    """
    active: dict[str, str] = {}

    selected = patterns if patterns is not None else list(PATTERNS)
    for name in selected:
        if name not in PATTERNS:
            raise ValueError(f"Unknown pattern '{name}'. Available: {list(PATTERNS)}")
        active[name] = PATTERNS[name]

    if custom_patterns:
        active.update(custom_patterns)

    result = text
    for regex in active.values():
        result = re.sub(regex, placeholder, result)
    return result


def mask_field(value: str, placeholder: str = "[REDACTED]") -> str:
    """Unconditionally mask an entire field value."""
    return placeholder if value else value
