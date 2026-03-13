"""Network-identifier PII recognizers: IP_ADDRESS, MAC_ADDRESS."""
from dataguard_deid.core.base_recognizer import PatternRecognizer

from dataguard_deid.config.scoring import SCORE_PROFILES
from dataguard_deid.patterns.dutch_patterns import IPV4_REGEX, IPV6_REGEX, MAC_REGEX
from dataguard_deid.recognizers._helpers import _p

_IP = SCORE_PROFILES["IP_ADDRESS"]
_MA = SCORE_PROFILES["MAC_ADDRESS"]


class NlIpRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("ipv4", IPV4_REGEX, _IP.base),
        _p("ipv6", IPV6_REGEX, _IP.base),
    ]
    CONTEXT = [
        "ip", "ip-adres", "ip address", "ipv4",
        "ipv6", "netwerk", "host", "serveradres",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IP_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlMacAddressRecognizer(PatternRecognizer):
    PATTERNS = [_p("mac", MAC_REGEX, _MA.base)]
    CONTEXT = [
        "mac", "mac-adres", "mac address",
        "bssid", "fysiek adres", "hardware adres",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="MAC_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
