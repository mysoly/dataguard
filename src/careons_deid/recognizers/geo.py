"""Geographic PII recognizers: GPS_COORDINATES, LICENCE_PLATE."""
from careons_deid.core.base_recognizer import PatternRecognizer

from careons_deid.config.scoring import SCORE_PROFILES
from careons_deid.patterns.dutch_patterns import GPS_REGEX, NL_PLATE_STRICT
from careons_deid.recognizers._helpers import _p

_GP = SCORE_PROFILES["GPS_COORDINATES"]
_LP = SCORE_PROFILES["LICENCE_PLATE"]


class NlGpsRecognizer(PatternRecognizer):
    PATTERNS = [_p("gps", GPS_REGEX, _GP.base)]
    CONTEXT = [
        "gps", "coördinaten", "locatie", "coordinates", "location",
        "lengtegraad", "breedtegraad", "lat", "lon", "latitude", "longitude",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="GPS_COORDINATES",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlLicencePlateRecognizer(PatternRecognizer):
    PATTERNS = [_p("nl_plate_strict", NL_PLATE_STRICT, _LP.base)]
    CONTEXT = [
        "kenteken", "nummerplaat", "nummerbord", "voertuig",
        "auto", "kentekenplaat", "kentekenbewijs", "chassisnummer", "vin",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="LICENCE_PLATE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
