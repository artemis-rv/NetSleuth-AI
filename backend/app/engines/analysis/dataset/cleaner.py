"""
cleaner.py
----------
M2 Phase 2 data cleaning for CICIDS2017.

Handles whitespace normalization, string-to-float conversion, NaN/Inf detection,
and duplicate row rejection.
"""

from __future__ import annotations

import math
from typing import Any, Optional

from app.engines.analysis.dataset.errors import DatasetCleaningError


def clean_row(raw_row: dict[str, str]) -> tuple[dict[str, float], str, str]:
    """Clean a single CSV row from CICIDS2017.
    
    Args:
        raw_row: Dictionary of raw string values from the CSV DictReader.
        
    Returns:
        A tuple of (numeric_features, raw_label, row_hash)
        
    Raises:
        DatasetCleaningError: If the row is malformed or contains fatal errors.
    """
    cleaned_features: dict[str, float] = {}
    raw_label = ""
    
    # We will build a deterministic string for hashing to detect duplicates.
    # We ignore the Timestamp and Flow ID if present, focusing on the metrics.
    hash_parts = []
    
    for key, value in raw_row.items():
        if key is None:
            continue
            
        clean_key = key.strip()
        clean_value = value.strip() if value else ""
        
        # The label column has inconsistent naming in CICIDS
        if clean_key == "Label" or clean_key.endswith("Label"):
            raw_label = clean_value
            continue
            
        # Ignore non-numeric metadata columns that might cause parsing errors
        if clean_key in ("Timestamp", "Flow ID", "Src IP", "Dst IP", "Source IP", "Destination IP"):
            continue
            
        # Try to parse as float
        try:
            if not clean_value:
                val = 0.0 # Missing values default to 0.0 in this context for numeric fields
            else:
                val = float(clean_value)
                
            # CICIDS sometimes contains 'Infinity' or 'NaN' strings which parse to float('inf') or float('nan')
            if not math.isfinite(val):
                raise DatasetCleaningError(f"Non-finite value '{clean_value}' for column '{clean_key}'")
                
            cleaned_features[clean_key] = val
            hash_parts.append(f"{clean_key}:{val:.4f}")
            
        except ValueError:
            # If it's not a float, and not the label, we skip it (could be an IP string we missed filtering)
            pass
            
    if not raw_label:
        raise DatasetCleaningError("Missing 'Label' column in row")
        
    # Create a simple hash of the deterministic row contents
    row_hash = hash(tuple(sorted(hash_parts)))
    # Ensure it's a positive string hash
    hash_str = hex(row_hash & ((1 << 64) - 1))[2:]
    
    return cleaned_features, raw_label, hash_str
