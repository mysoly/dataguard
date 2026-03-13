"""
Label group mapping for grouped output mode.

LABEL_GROUPS maps every sub-label (entity type) to its parent group label.
Custom pattern entity types not present in this dict fall back to their own
name when grouped_labels is active.
"""

LABEL_GROUPS: dict[str, str] = {
    "PERSON":           "PERSON",
    "DATE":             "DATETIME",
    "TIME":             "DATETIME",
    "PHONE_NUMBER":     "CONTACT",
    "FAX_NUMBER":       "CONTACT",
    "EMAIL_ADDRESS":    "CONTACT",
    "URL":              "CONTACT",
    "ZIPCODE":          "LOCATION",
    "GPS_COORDINATES":  "LOCATION",
    "LOCATION":         "LOCATION",
    "IBAN_CODE":        "FINANCIAL",
    "CREDIT_CARD":      "FINANCIAL",
    "CVV":              "FINANCIAL",
    "BSN":              "IDENTIFIER",
    "PASSPORT":         "IDENTIFIER",
    "ZORGPOLIS_NUMBER": "IDENTIFIER",
    "IP_ADDRESS":       "DEVICE_IDENTIFIER",
    "MAC_ADDRESS":      "DEVICE_IDENTIFIER",
    "IMEI":             "DEVICE_IDENTIFIER",
    "LICENCE_PLATE":    "VEHICLE_IDENTIFIER",
}
