"""
Dutch-specific keywords for PII detection.
Extracted from dutch_patterns.py for better maintainability.
"""

# DATE MONTHS
DATE_MONTHS_NL = (
    r"januari|jan|februari|feb|maart|mar|april|mei|juni|jun|juli|jul"
    r"|augustus|aug|september|sep|oktober|okt|november|nov|december|dec"
)

# English month names (for cross-lingual / ISO-locale datasets)
DATE_MONTHS_EN = (
    r"january|february|march|april|may|june|july"
    r"|august|september|october|november|december"
)

# GENDER
GENDER_KEYWORDS_NL = (
    r"man|vrouw|jongen|meid|meisje|jongetje|mannen|vrouwen"
    r"|meneer|non-binaire?|mevrouw|mr\.|m\."
)

# RELIGION
RELIGIOUS_KEYWORDS_NL = (
    r"rooms-katholieks?|rooms-katholicisme|grieks-orthodox[e]?|oost-orthodox[e]?"
    r"|protestants?|christelijke?|christen|katholicisme|katholieks?"
    r"|evangelisch[e]?|anglicaans[e]?|luthers[e]?"
    r"|muslims?|moslims?|islamitisch[e]?|islam|sji[i\u00ef]tisch[e]?|soennitisch[e]?"
    r"|joden?|joods?[e]?|judaïsme|judaisme"
    r"|boeddhisten?|boeddha|boeddhisme"
    r"|hindoes?|hindoeïsme|hindoeisme"
    r"|sikh[s]?|sikhisme|atheïstisch[e]?|agnostisch[e]?|niet-religieus"
)

# CVV / Security 
CVV_KEYWORDS = r"cvv2?|cvc2?|cid"
SECURITY_CODE_KEYWORDS = r"beveiligingscode|veiligheidscode|kaartverificatiecode"
