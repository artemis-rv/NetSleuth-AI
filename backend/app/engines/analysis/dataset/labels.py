"""
labels.py
---------
M2 Phase 2 canonical label normalisation for CICIDS2017.

Maps the original CICIDS string labels to the M2 V1 ActivityClass taxonomy.
Labels that cannot be safely mapped are assigned to UNMAPPED.
"""

from __future__ import annotations

from app.contracts.analysis import ActivityClass

# Special constant for labels that do not map to the M2 taxonomy.
UNMAPPED = "UNMAPPED"

# ---------------------------------------------------------------------------
# NORMALISATION MAPPING
# ---------------------------------------------------------------------------
# Maps exact string values from the CICIDS2017 'Label' column to
# either an ActivityClass enum member or UNMAPPED.
CICIDS_TO_M2_MAPPING: dict[str, ActivityClass | str] = {
    # Benign
    "BENIGN": ActivityClass.BENIGN,
    
    # Scanning & Reconnaissance
    "FTP-Patator": ActivityClass.SCANNING_RECONNAISSANCE,
    "FTP-Patator - Attempted": ActivityClass.SCANNING_RECONNAISSANCE,
    "SSH-Patator": ActivityClass.SCANNING_RECONNAISSANCE,
    "SSH-Patator - Attempted": ActivityClass.SCANNING_RECONNAISSANCE,
    "Portscan": ActivityClass.SCANNING_RECONNAISSANCE,
    "Infiltration - Portscan": ActivityClass.SCANNING_RECONNAISSANCE,
    
    # Volumetric / C2 / Botnet -> C2_MALWARE_COMMUNICATION
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
    
    # Exfiltration / Deep Infiltration
    "Infiltration": ActivityClass.POSSIBLE_EXFILTRATION,
    "Infiltration - Attempted": ActivityClass.POSSIBLE_EXFILTRATION,
    
    # Web Attacks
    "Web Attack - Brute Force": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - Brute Force - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - SQL Injection": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - SQL Injection - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - XSS": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    "Web Attack - XSS - Attempted": ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    
    # Unmapped (TLS exploit, no good fit in current taxonomy)
    "Heartbleed": UNMAPPED,
}


def normalize_label(raw_label: str) -> ActivityClass | str:
    """Map a raw CICIDS label string to the M2 ActivityClass taxonomy.
    
    Args:
        raw_label: The raw string from the CSV.
        
    Returns:
        The corresponding ActivityClass, or UNMAPPED if no safe mapping exists.
    """
    clean_label = raw_label.strip()
    return CICIDS_TO_M2_MAPPING.get(clean_label, UNMAPPED)
