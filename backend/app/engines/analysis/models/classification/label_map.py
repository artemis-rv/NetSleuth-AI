"""
label_map.py
------------
M2 Phase 6 — Canonical label mapping and validation for CICIDS2017 dataset.

Maps original CICIDS2017 string labels to the frozen M2 ActivityClass taxonomy.
Labels that cannot be safely or unambiguously mapped are assigned to UNMAPPED.
Uncertain or unmapped labels are NEVER silently converted or coerced.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.contracts.analysis import ActivityClass
from app.engines.analysis.dataset.labels import UNMAPPED
from app.engines.analysis.models.classification.errors import LabelMappingError

logger = logging.getLogger(__name__)

LABEL_MAPPING_VERSION = "CICIDS2017-v1-label-map"

# All 6 canonical behavioral activity classes in the M2 V1 taxonomy.
# Note: MITRE ATT&CK technique IDs and tactic names are strictly forbidden here (M3 responsibility).
ALL_ACTIVITY_CLASSES: list[ActivityClass] = [
    ActivityClass.BENIGN,
    ActivityClass.C2_MALWARE_COMMUNICATION,
    ActivityClass.DNS_ANOMALY_TUNNELING,
    ActivityClass.SCANNING_RECONNAISSANCE,
    ActivityClass.POSSIBLE_EXFILTRATION,
    ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
]

# ---------------------------------------------------------------------------
# CICIDS SOURCE-LABEL TO M2 ACTIVITY TAXONOMY MAPPING TABLE
# ---------------------------------------------------------------------------
# Explicit mapping dictionary from raw CICIDS string labels to M2 ActivityClass.
# Any label not explicitly listed here or mapped to UNMAPPED will NOT be silently
# converted to BENIGN or any valid ActivityClass.
CICIDS_LABEL_MAP: dict[str, ActivityClass | str] = {
    # Benign traffic
    "BENIGN": ActivityClass.BENIGN,

    # Scanning & Reconnaissance
    "FTP-Patator": ActivityClass.SCANNING_RECONNAISSANCE,
    "FTP-Patator - Attempted": ActivityClass.SCANNING_RECONNAISSANCE,
    "SSH-Patator": ActivityClass.SCANNING_RECONNAISSANCE,
    "SSH-Patator - Attempted": ActivityClass.SCANNING_RECONNAISSANCE,
    "Portscan": ActivityClass.SCANNING_RECONNAISSANCE,
    "Infiltration - Portscan": ActivityClass.SCANNING_RECONNAISSANCE,

    # Volumetric DoS / DDoS / Botnet Command & Control -> C2_MALWARE_COMMUNICATION
    "DoS GoldenEye": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS GoldenEye - Attempted": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Hulk": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Hulk - Attempted": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Slowhttptest": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Slowhttptest - Attempted": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Slowloris": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DoS Slowloris - Attempted": ActivityClass.C2_MALWARE_COMMUNICATION,
    "DDoS": ActivityClass.C2_MALWARE_COMMUNICATION,
    "Botnet": ActivityClass.C2_MALWARE_COMMUNICATION,
    "Botnet - Attempted": ActivityClass.C2_MALWARE_COMMUNICATION,

    # Infiltration / Data Movement -> POSSIBLE_EXFILTRATION
    "Infiltration": ActivityClass.POSSIBLE_EXFILTRATION,
    "Infiltration - Attempted": ActivityClass.POSSIBLE_EXFILTRATION,

    # Web-based Exploitation -> SUSPICIOUS_WEB_ACTIVITY
    "Web Attack - Brute Force": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - Brute Force - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - SQL Injection": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - SQL Injection - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - XSS": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - XSS - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,

    # Explicitly Unmapped (TLS Exploit - does not fit behavioral taxonomy safely)
    "Heartbleed": UNMAPPED,
}


def map_cicids_label(raw_label: str, strict: bool = False) -> ActivityClass | str:
    """Map a raw CICIDS label string to the M2 ActivityClass taxonomy.

    Args:
        raw_label: Raw label string from source dataset.
        strict: If True, raises LabelMappingError for unmapped/unknown labels.

    Returns:
        The mapped ActivityClass member, or UNMAPPED if unmapped and strict=False.

    Raises:
        LabelMappingError: If strict=True and the label is unknown or UNMAPPED.
    """
    cleaned = raw_label.strip() if isinstance(raw_label, str) else ""
    mapped = CICIDS_LABEL_MAP.get(cleaned, UNMAPPED)

    if mapped == UNMAPPED:
        logger.warning(
            "Source label '%s' (cleaned: '%s') cannot be mapped safely to M2 taxonomy.",
            raw_label,
            cleaned,
        )
        if strict:
            raise LabelMappingError(
                f"Cannot map uncertain or unmapped source label '{raw_label}' to M2 taxonomy"
            )

    return mapped


def validate_activity_class(value: str | ActivityClass) -> ActivityClass:
    """Ensure a string or enum is a valid member of ActivityClass.

    Raises:
        LabelMappingError: If value is not a valid ActivityClass.
    """
    if isinstance(value, ActivityClass):
        return value

    try:
        return ActivityClass(str(value))
    except ValueError:
        raise LabelMappingError(f"Invalid ActivityClass value: '{value}'")
