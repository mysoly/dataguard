# Careons PII Guard — Dutch PII Detection & Anonymization

> **Detect, mask, and anonymize Personally Identifiable Information (PII) in Dutch text and documents.**  
> Built for Dutch healthcare, GDPR / AVG compliance, and NEN 7510 data-protection pipelines.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What is Careons PII Guard?

**Careons PII Guard** is a Python library that detects and anonymizes Dutch PII in both plain text and documents (`.pdf`, `.docx`, `.txt`). It combines:

- **Custom Dutch regex recognizers** — 20+ hand-tuned patterns for Dutch identifiers (BSN, IBAN, Zorgpolis, licence plates, …)
- **spaCy Dutch NER** (`nl_core_news_lg`) — neural named-entity recognition for persons and locations
- **Algorithmic validation** — elfproef for BSN, mod-97 for IBAN, Luhn for credit cards and IMEI
- **Context-aware scoring** — keyword windows boost confidence before anonymization decisions

Use cases: de-identifying patient records, anonymizing clinical notes, sanitizing intake forms, GDPR / AVG data-minimization pipelines, NEN 7510 technical controls.

---

## Key Features

| Feature | Detail |
|---------|--------|
| **22 entity types** | Full Dutch PII coverage — from BSN and Zorgpolis to GPS coordinates and blood type |
| **Catch-all number detection** | `UNK_NUMBER` tags any unrecognized digit sequence (≥ 3 digits) not claimed by a named entity |
| **3 guard modes** | `anonymize` (realistic Dutch fakes) · `tag` (`[PERSON]`) · `i_tag` (`[PERSON_1]`) |
| **Document support** | Reads `.pdf` (pypdf), `.docx` (python-docx), and `.txt` natively |
| **PDF normalization** | Automatically repairs pypdf extraction artifacts (double spaces, word-per-line scattering) |
| **Algorithmic validation** | BSN elfproef · IBAN mod-97 · Credit card & IMEI Luhn |
| **Context-aware scoring** | Keyword windows around matches boost confidence scores before thresholding |
| **Entity filtering** | `keep` allowlist or `ignore` denylist per call |
| **Custom patterns** | Plug in your own regex with optional context words and fake-value pools |
| **Length-matched anonymization** | `UNK_NUMBER` fakes preserve the exact digit count and separator structure of the original |
| **GDPR / AVG ready** | Designed for Dutch healthcare data pipelines and NEN 7510 technical controls |

---

## Installation

```bash
pip install careons-deid
```

Download the Dutch spaCy model (required for `PERSON` and `LOCATION` detection):

```bash
python -m spacy download nl_core_news_lg
```

Document support requires optional dependencies:

```bash
pip install pypdf          # PDF support
pip install python-docx    # DOCX support
```

---

## Quick Start

```python
from careons_deid import analyze, guard

text = "Mijn naam is Jan de Vries en ik woon in Amsterdam. Mijn BSN is 123456782."

# ── Detect PII ────────────────────────────────────────────────────
findings = analyze.text(text)
for f in findings:
    print(f"[{f['type']}] {text[f['start']:f['end']]} (score: {f['score']})")
# [PERSON]   Jan de Vries  (score: 0.85)
# [LOCATION] Amsterdam     (score: 0.85)
# [BSN]      123456782     (score: 0.85)

# ── Anonymize (default mode) ──────────────────────────────────────
result = guard.text(text)
print(result["guarded_text"])
# "Mijn naam is Maria Janssen en ik woon in Utrecht. Mijn BSN is 111222333."

# ── Tag mode ──────────────────────────────────────────────────────
print(guard.text(text, config={"mode": "tag"})["guarded_text"])
# "Mijn naam is [PERSON] en ik woon in [LOCATION]. Mijn BSN is [BSN]."

# ── Indexed tag mode ──────────────────────────────────────────────
print(guard.text(text, config={"mode": "i_tag"})["guarded_text"])
# "Mijn naam is [PERSON_1] en ik woon in [LOCATION_1]. Mijn BSN is [BSN_1]."
```

---

## Document Processing

Process files directly — text extraction and PII analysis in one call:

```python
from careons_deid import analyze, guard

# Analyze a file
findings = analyze.doc("patient_report.pdf")
findings = analyze.doc("intake_form.docx")
findings = analyze.doc("clinical_note.txt")

# Anonymize a file
result = guard.doc("patient_report.pdf")
print(result["guarded_text"])   # clean, anonymized text
print(result["findings"])       # list of detected PII spans

# All config options work the same as with .text()
result = guard.doc("intake_form.docx", config={
    "mode": "tag",
    "score_threshold": 0.6,
    "set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]},
})
```

**Supported formats:**

| Format | Reader | Notes |
|--------|--------|-------|
| `.txt` | built-in `open()` | UTF-8 |
| `.pdf` | `pypdf` | All pages concatenated; spacing artifacts auto-normalized |
| `.docx` | `python-docx` | All paragraphs joined |

Any other extension raises `UnsupportedFormatError` before the file-existence check.

---

## Supported Entity Types

| Entity | Description | Validation |
|--------|-------------|------------|
| `PERSON` | Person names | spaCy NER |
| `LOCATION` | Cities, addresses, regions | spaCy NER |
| `DATE` | Dates (numeric & Dutch month names) | — |
| `TIME` | Times (12h / 24h / Dutch "uur") | — |
| `PHONE_NUMBER` | Dutch mobile & landline, EU format | — |
| `EMAIL_ADDRESS` | E-mail addresses | — |
| `ZIPCODE` | Dutch postal codes (`1234 AB`) | — |
| `URL` | HTTP/HTTPS/FTP links | — |
| `IBAN_CODE` | Dutch & international IBANs | ✓ ISO 13616 mod-97 |
| `CREDIT_CARD` | Visa, Mastercard, Amex, Diners, Discover, JCB | ✓ Luhn |
| `CVV` | Card security codes (context-required) | — |
| `BSN` | Burgerservicenummer | ✓ Elfproef (11-proef) |
| `PASSPORT` | Dutch passport numbers | — |
| `IMEI` | Mobile device identifiers (15 digits) | ✓ Luhn |
| `LICENCE_PLATE` | Dutch vehicle licence plates | — |
| `IP_ADDRESS` | IPv4 and IPv6 addresses | — |
| `MAC_ADDRESS` | Ethernet MAC addresses | — |
| `GPS_COORDINATES` | Latitude / longitude pairs | — |
| `ZORGPOLIS_NUMBER` | Dutch health insurance policy numbers | — |
| `GENDER` | Gender references (context-boosted) | — |
| `BLOOD_TYPE` | Blood group (A/B/AB/O ±) | — |
| `RELIGION` | Religious affiliation references | — |
| `UNK_NUMBER` | Catch-all: any unrecognized digit sequence ≥ 3 digits | — |

---

## Guard Modes

| Mode | Behaviour | Output example |
|------|-----------|----------------|
| `anonymize` *(default)* | Replace each entity with a realistic Dutch synthetic value | `Jan Bakker`, `111222333`, `NL20 INGB 0001 2345 67` |
| `tag` | Replace with `[ENTITY_TYPE]` | `[PERSON]`, `[BSN]`, `[IBAN_CODE]` |
| `i_tag` | Replace with `[ENTITY_TYPE_N]` — same entity type gets the same index | `[PERSON_1]` … `[PERSON_2]` |

`UNK_NUMBER` is anonymized with a **length-matched** random digit string that preserves the original's structure (digits replaced, separators like spaces and dashes kept in place).

---

## Configuration

All options are passed via a single `config` dict:

```python
# Allowlist — only detect these entity types
config = {"set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]}}

# Denylist — detect everything except these
config = {"set_entities": {"ignore": ["DATE", "GENDER"]}}

# Full config example
config = {
    "set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]},

    # Minimum confidence to include a finding
    "score_threshold": 0.5,

    # Guard mode
    "mode": "anonymize",   # "anonymize" | "tag" | "i_tag"

    # Custom patterns (see below)
    "custom_patterns": [...],
}
```

### Custom Patterns

```python
from careons_deid import analyze, guard, custom_pattern

emp = custom_pattern(
    name="EMPLOYEE_ID",
    regex=r"EMP-\d{4}",
    score=0.9,
    context=["medewerker", "werknemer"],        # nearby words boost score
    anonymize_list=["EMP-9999", "EMP-8888"],    # fake pool for anonymize mode
)

findings = analyze.text("Medewerker EMP-1234 heeft toegang.", config={"custom_patterns": [emp]})
guarded  = guard.text("Medewerker EMP-1234 heeft toegang.",  config={"custom_patterns": [emp]})
print(guarded["guarded_text"])
# "Medewerker EMP-9999 heeft toegang."
```

---

## Scoring & Confidence

Every finding carries a `score` between 0 and 1. Scores are determined by:

1. **Regex match only** (`base`) — pattern fires, no additional evidence
2. **Context boost** (`with_context`) — a relevant keyword appears within 120 characters
3. **Algorithmic validation** (`validated`) — checksum passes (elfproef / mod-97 / Luhn)
4. **High confidence** (`high_confidence`) — validation *and* context keyword present (BSN, IMEI, Zorgpolis)

Use `score_threshold` to filter out low-confidence results before anonymization.

---

## Package Layout

```
careons_deid/
├── core/
│   ├── types.py           — internal data structures (RecognizerResult, Pattern, …)
│   ├── base_recognizer.py — EntityRecognizer / PatternRecognizer base classes
│   ├── base_spacy.py      — spaCy NER base class
│   ├── analyzer.py        — analysis engine wrapper + entity resolution
│   └── guard.py           — guard engine wrapper
├── processors/
│   ├── text_processor.py  — analyze / guard pipelines for plain-text input
│   └── doc_processor.py   — file reading (.pdf / .docx / .txt) + normalization
├── recognizers/           — 20+ custom Dutch recognizers
├── patterns/              — Dutch regex patterns & keyword lists
├── config/                — entity list, scoring profiles
└── anonymization/         — fake-data pools + FakeDataProvider
```

The public interface is exposed through two namespace objects in `careons_deid/__init__.py`:

```python
from careons_deid import analyze, guard, custom_pattern
```

---

## Privacy & Compliance

| Standard | How this library helps |
|----------|----------------------|
| **GDPR / AVG** | De-identifies personal data before storage or transfer; supports data-minimization obligations |
| **NEN 7510** | Provides a technical control layer for pseudonymization of Dutch patient data |
| **Human-in-the-loop** | Automated detection is probabilistic — for critical clinical datasets, always include human review of anonymized output |

> This library is a **technical tool**, not a legal guarantee. Your full pipeline architecture, access controls, and data governance policies must meet the applicable regulatory requirements.

---

## Interactive Quickstart

The [examples/quickstart.ipynb](examples/quickstart.ipynb) notebook covers:

- Text and document analysis
- All three guard modes
- Dutch healthcare identifiers (BSN, Zorgpolis)
- Custom patterns with anonymization pools
- Entity filtering and score thresholds
- Error handling for unsupported file formats

---

## License

MIT License — see [LICENSE](LICENSE) for details.
