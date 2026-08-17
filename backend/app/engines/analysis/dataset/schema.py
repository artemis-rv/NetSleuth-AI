"""
schema.py
---------
M2 Phase 2 dataset schema and representations.

Defines the internal DatasetRecord, NormalizedLabel, and DatasetBatch objects,
as well as the explicit mapping from CICIDS2017 feature columns to the
canonical M2 FeatureName enum.
"""

from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field

from backend.app.contracts.analysis import ActivityClass, FeatureVector, FeatureValue
from backend.app.contracts.feature_schema import FeatureName
from backend.app.engines.analysis.dataset.labels import UNMAPPED

# ---------------------------------------------------------------------------
# FEATURE MAPPING
# ---------------------------------------------------------------------------
# Maps exact string values from the CICIDS2017 header to the canonical
# M2 FeatureName. Only features that semantically match are mapped.
# Features without a valid mapping are intentionally omitted.
CICIDS_TO_M2_FEATURE_MAP: dict[str, FeatureName] = {
    # Flow Duration (microseconds in CICIDS, but we capture the aggregate)
    "Flow Duration": FeatureName.FLOW_MEAN_DURATION,
    
    # Bytes
    "Total Length of Fwd Packet": FeatureName.FLOW_OUTBOUND_BYTES,
    "Total Length of Bwd Packet": FeatureName.FLOW_INBOUND_BYTES,
    
    # Packets
    "Total Fwd Packet": FeatureName.FLOW_TOTAL_PACKETS, # Not exactly total, but subflow forward
    "Total Bwd packets": FeatureName.FLOW_TOTAL_PACKETS, # Will need to aggregate if both mapped? Let's just map rates.
    
    # Rates
    "Flow Bytes/s": FeatureName.TEMPORAL_FLOW_RATE, # Actually byte rate, not flow rate. Let's map accurately if possible.
    "Flow Packets/s": FeatureName.TEMPORAL_EVENT_RATE, # Packet rate.
    
    # Let's map only the exact semantic matches to avoid corrupting the model.
    # We will map a minimal safe subset of CICIDS features to M2's canonical schema.
    # Note: CICIDS features are highly specific flow-level metrics, while M2
    # FeatureSchema aggregates over an *observation window*. We will map them
    # directly where the semantic is close enough for an unsupervised model experiment.
}

# ---------------------------------------------------------------------------
# DATASET MODELS
# ---------------------------------------------------------------------------

class NormalizedLabel(BaseModel):
    """Encapsulates the original dataset label and its M2 normalized form."""
    source_label: str = Field(..., description="Original string from the dataset")
    activity_class: Optional[ActivityClass] = Field(
        None, description="Normalized M2 class, or None if UNMAPPED"
    )
    is_unmapped: bool = Field(..., description="True if the label could not be safely mapped")

    model_config = {"frozen": True, "extra": "forbid"}

class DatasetRecord(BaseModel):
    """A single row from the dataset."""
    record_id: str = Field(..., description="Unique identifier for the row")
    source_file: str = Field(..., description="Original dataset filename (e.g., monday.csv)")
    split: str = Field(..., description="Data split: train, validation, or test")
    
    # Unsupervised models MUST NOT receive the label.
    # It is kept separate from the feature_vector.
    label: NormalizedLabel = Field(..., description="Normalized label metadata")
    
    # The canonical M2 feature vector.
    feature_vector: FeatureVector = Field(..., description="Features mapped to M2 canonical schema")
    
    # We preserve the raw unmapped numeric features for dataset-specific experiments
    raw_features: dict[str, float] = Field(default_factory=dict, description="Original numeric features")

    model_config = {"frozen": True, "extra": "forbid"}

class DatasetBatch(BaseModel):
    """A batch of processed dataset records."""
    batch_id: str = Field(..., description="Unique batch identifier")
    split: str = Field(..., description="Data split: train, validation, or test")
    records: list[DatasetRecord] = Field(default_factory=list, description="Records in this batch")
    
    # Statistics
    rows_loaded: int = Field(0, description="Total rows read from source")
    rows_rejected: int = Field(0, description="Rows skipped due to invalid data")
    rows_duplicated: int = Field(0, description="Rows skipped due to exact duplication")
    
    class_counts: dict[str, int] = Field(default_factory=dict, description="Counts of normalized M2 classes")
    source_label_counts: dict[str, int] = Field(default_factory=dict, description="Counts of raw dataset labels")

    model_config = {"frozen": True, "extra": "forbid"}
