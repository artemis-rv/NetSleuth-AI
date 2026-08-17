"""
dataset package
---------------
M2 Phase 2 CICIDS2017 dataset ingestion.
"""

from .errors import DatasetError, DatasetFileNotFoundError, DatasetCleaningError
from .schema import DatasetBatch, DatasetRecord, NormalizedLabel
from .labels import normalize_label, UNMAPPED
from .loader import load_dataset_file, determine_split
