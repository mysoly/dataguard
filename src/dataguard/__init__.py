"""dataguard – simple regex-based data masking."""

from .masker import PATTERNS, mask, mask_field

__version__ = "0.3.0"
__all__ = ["mask", "mask_field", "PATTERNS"]
