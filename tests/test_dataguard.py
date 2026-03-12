import pytest
import dataguard
from dataguard import mask, mask_field, PATTERNS


def test_version_exists():
    assert dataguard.__version__ == "0.1.0"


class TestEmail:
    def test_basic(self):
        assert mask("Contact: user@example.com please") == "Contact: [REDACTED] please"

    def test_multiple(self):
        result = mask("a@b.com and c@d.org")
        assert result == "[REDACTED] and [REDACTED]"

    def test_no_match(self):
        assert mask("no email here", patterns=["email"]) == "no email here"


class TestCreditCard:
    def test_spaced(self):
        assert "[REDACTED]" in mask("Card: 4111 1111 1111 1111", patterns=["credit_card"])

    def test_dashed(self):
        assert "[REDACTED]" in mask("4111-1111-1111-1111", patterns=["credit_card"])


class TestSSN:
    def test_dashes(self):
        assert mask("SSN: 123-45-6789", patterns=["ssn"]) == "SSN: [REDACTED]"

    def test_spaces(self):
        assert mask("SSN: 123 45 6789", patterns=["ssn"]) == "SSN: [REDACTED]"


class TestIPv4:
    def test_basic(self):
        assert mask("Server at 192.168.1.1", patterns=["ipv4"]) == "Server at [REDACTED]"


class TestCustomPlaceholder:
    def test_placeholder(self):
        result = mask("user@test.com", patterns=["email"], placeholder="***")
        assert result == "***"


class TestCustomPatterns:
    def test_custom(self):
        result = mask("Order #ORD-12345", custom_patterns={"order": r"ORD-\d+"})
        assert "[REDACTED]" in result

    def test_unknown_pattern_raises(self):
        with pytest.raises(ValueError, match="Unknown pattern"):
            mask("text", patterns=["nonexistent"])


class TestMaskField:
    def test_masks_value(self):
        assert mask_field("secret") == "[REDACTED]"

    def test_empty_passthrough(self):
        assert mask_field("") == ""

    def test_custom_placeholder(self):
        assert mask_field("data", placeholder="***") == "***"


def test_patterns_dict_has_expected_keys():
    for key in ("email", "credit_card", "phone", "ssn", "ipv4", "iban"):
        assert key in PATTERNS
