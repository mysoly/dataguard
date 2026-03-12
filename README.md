# dataguard

Simple regex-based sensitive data masking for Python.

## Installation

```bash
pip install test-dataguard
```

## Usage

```python
from dataguard import mask, mask_field

# Mask with all built-in patterns
text = "Contact user@example.com or call +1-800-555-0100"
print(mask(text))
# → "Contact [REDACTED] or call [REDACTED]"

# Select specific patterns
print(mask(text, patterns=["email"]))
# → "Contact [REDACTED] or call +1-800-555-0100"

# Custom placeholder
print(mask("SSN: 123-45-6789", patterns=["ssn"], placeholder="***"))
# → "SSN: ***"

# Add your own regex patterns
print(mask("Order #ORD-9981", custom_patterns={"order_id": r"ORD-\d+"}))
# → "Order #[REDACTED]"

# Unconditionally mask a field value
print(mask_field("super-secret-token"))
# → "[REDACTED]"
```

## Built-in patterns

| Name          | Matches                        |
|---------------|--------------------------------|
| `email`       | Email addresses                |
| `credit_card` | 13–16 digit card numbers       |
| `phone`       | International phone numbers    |
| `ssn`         | US Social Security Numbers     |
| `ipv4`        | IPv4 addresses                 |
| `iban`        | IBAN bank account numbers      |

## API

### `mask(text, patterns=None, placeholder="[REDACTED]", custom_patterns=None)`

Returns *text* with all pattern matches replaced by *placeholder*.

- `patterns` – list of built-in pattern names to apply (default: all).
- `custom_patterns` – `dict[str, str]` of extra `{name: regex}` patterns.

### `mask_field(value, placeholder="[REDACTED]")`

Replaces *value* entirely with *placeholder*. Useful for known-sensitive fields.

## License

MIT
