"""
loader.py
---------
M2 Phase 2 dataset loader for CICIDS2017.

Loads CSV files, cleans rows, normalizes labels, maps features to the M2
canonical schema, and assigns splits based on the day of the week.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from uuid import uuid4
from collections import Counter

from app.contracts.analysis import FeatureVector, FeatureValue
from app.engines.analysis.dataset.errors import DatasetFileNotFoundError, DatasetCleaningError
from app.engines.analysis.dataset.labels import normalize_label, UNMAPPED
from app.engines.analysis.dataset.schema import (
    DatasetBatch,
    DatasetRecord,
    NormalizedLabel,
    CICIDS_TO_M2_FEATURE_MAP,
)

logger = logging.getLogger(__name__)


def determine_split(filename: str) -> str:
    """Determine the deterministic split based on the CICIDS2017 filename.
    
    TRAIN: monday, tuesday, wednesday
    VALIDATION: thursday
    TEST: friday
    """
    name = filename.lower()
    if "monday" in name or "tuesday" in name or "wednesday" in name:
        return "train"
    elif "thursday" in name:
        return "validation"
    elif "friday" in name:
        return "test"
    else:
        return "unknown"


def load_dataset_file(filepath: Path | str, acquisition_id: str = "CICIDS2017") -> DatasetBatch:
    """Load a single CICIDS2017 CSV file into a DatasetBatch.
    
    Args:
        filepath: Path to the CSV file (e.g., 'monday.csv')
        acquisition_id: Optional ID to tie back to M2 contracts.
        
    Returns:
        A fully processed DatasetBatch.
        
    Raises:
        DatasetFileNotFoundError: If the file does not exist.
    """
    path = Path(filepath)
    if not path.is_file():
        raise DatasetFileNotFoundError(f"Dataset file not found: {path}")
        
    filename = path.name
    split = determine_split(filename)
    batch_id = f"BATCH-{uuid4().hex[:8].upper()}"
    
    records: list[DatasetRecord] = []
    seen_hashes = set()
    
    rows_loaded = 0
    rows_rejected = 0
    rows_duplicated = 0
    class_counts = Counter()
    source_label_counts = Counter()
    
    from app.engines.analysis.dataset.cleaner import clean_row
    
    # Using errors='replace' to handle potential unicode encoding issues in CICIDS
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows_loaded += 1
            
            try:
                numeric_features, raw_label, row_hash = clean_row(row)
            except DatasetCleaningError as e:
                logger.debug("Rejected row %d in %s: %s", rows_loaded, filename, e)
                rows_rejected += 1
                continue
                
            if row_hash in seen_hashes:
                rows_duplicated += 1
                continue
                
            seen_hashes.add(row_hash)
            
            # Label normalisation
            activity_class = normalize_label(raw_label)
            is_unmapped = activity_class == UNMAPPED
            
            norm_label = NormalizedLabel(
                source_label=raw_label,
                activity_class=None if is_unmapped else activity_class,
                is_unmapped=is_unmapped
            )
            
            # Map to canonical FeatureVector
            feature_values = []
            for cic_name, m2_name in CICIDS_TO_M2_FEATURE_MAP.items():
                val = numeric_features.get(cic_name)
                # Map to FeatureValue. We only map what we have.
                # If absent, we still add it but with present=False if val is None
                # Since cleaner returns 0.0 for missing float fields we might have 0.0,
                # but let's be exact.
                if cic_name in numeric_features:
                    feature_values.append(
                        FeatureValue(
                            name=m2_name.value,
                            value=val,
                            present=True,
                            categorical=False
                        )
                    )
                    
            feature_vector = FeatureVector(
                vector_id=f"FV-{uuid4().hex[:12].upper()}",
                acquisition_id=acquisition_id,
                features=feature_values
            )
            
            record = DatasetRecord(
                record_id=f"REC-{uuid4().hex[:12].upper()}",
                source_file=filename,
                split=split,
                label=norm_label,
                feature_vector=feature_vector,
                raw_features=numeric_features
            )
            
            records.append(record)
            
            source_label_counts[raw_label] += 1
            if is_unmapped:
                class_counts[UNMAPPED] += 1
            else:
                class_counts[activity_class.value] += 1

    return DatasetBatch(
        batch_id=batch_id,
        split=split,
        records=records,
        rows_loaded=rows_loaded,
        rows_rejected=rows_rejected,
        rows_duplicated=rows_duplicated,
        class_counts=dict(class_counts),
        source_label_counts=dict(source_label_counts)
    )
