"""Contact-detail PII recognizers: PHONE_NUMBER, EMAIL_ADDRESS, ZIPCODE, URL."""
from dataguard_deid.core.base_recognizer import PatternRecognizer

from dataguard_deid.config.scoring import SCORE_PROFILES
from dataguard_deid.patterns.dutch_patterns import (
    EU_PHONES, PHONE_INTL, LOCAL_PHONES, PHONE_NL_MOBILE,
    EMAIL_REGEX, ZIP_REGEX_NL, WEBSITE_REGEX, WEBSITE_REGEX_WWW,
)
from dataguard_deid.recognizers._helpers import _p

_PH = SCORE_PROFILES["PHONE_NUMBER"]
_EM = SCORE_PROFILES["EMAIL_ADDRESS"]
_ZI = SCORE_PROFILES["ZIPCODE"]
_UR = SCORE_PROFILES["URL"]


class NlPhoneRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("nl_mobile",   PHONE_NL_MOBILE, 0.70),   # most specific — first
        _p("eu_phone",    EU_PHONES,       0.40),
        _p("intl_phone",  PHONE_INTL,      0.35),   # flexible intl +CC x-x-x; low base
        _p("local_phone", LOCAL_PHONES,    _PH.base),
    ]
    CONTEXT = [
        "telefoon", "tel", "mobiel", "phone", "bel", "gsm",
        "nummer", "telefoonnummer", "06", "contactnummer",
        "werktelefoon", "whatsapp",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlEmailRecognizer(PatternRecognizer):
    PATTERNS = [_p("email", EMAIL_REGEX, _EM.base)]
    CONTEXT = [
        "e-mail", "email", "mail", "e-mailadres",
        "emailadres", "mailadres", "contact",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="EMAIL_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlZipcodeRecognizer(PatternRecognizer):
    PATTERNS = [_p("nl_zip", ZIP_REGEX_NL, _ZI.base)]
    CONTEXT = ["postcode", "zip", "pc", "postadres", "huisnummer", "woonplaats"]

    def __init__(self):
        super().__init__(
            supported_entity="ZIPCODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlUrlRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("url_schemed", WEBSITE_REGEX,     _UR.base),   # https?:// or ftp://
        _p("url_www",     WEBSITE_REGEX_WWW, _UR.base),   # www.example.com
    ]
    CONTEXT = [
        "website", "url", "link", "site",
        "webpagina", "webadres", "domein", "domeinnaam",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
