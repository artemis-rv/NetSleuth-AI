"""
contracts package
-----------------
Public interface for all NetSleuth-AI shared contracts.

M1 contract: network_intelligence.py
M2 contract: analysis.py, feature_schema.py
"""

from .network_intelligence import (  # noqa: F401
    CONTRACT_VERSION,
    AcquisitionReference,
    Artifact,
    ArtifactProvenance,
    ArtifactType,
    DNSData,
    Endpoint,
    EventProvenance,
    Flow,
    FlowProvenance,
    HTTPData,
    NetworkIntelligencePackage,
    PacketReference,
    Protocol,
    ProtocolEvent,
    Provenance,
    TLSData,
)

from .analysis import (  # noqa: F401
    M2_CONTRACT_VERSION,
    ActivityClass,
    AnomalyResult,
    ClassificationResult,
    EvidenceReference,
    FeatureValue,
    FeatureVector,
    Finding,
    FindingsPackage,
)

from .feature_schema import (  # noqa: F401
    FEATURE_SCHEMA,
    FEATURE_SCHEMA_VERSION,
    FeatureDescriptor,
    FeatureName,
    schema_feature_names,
    schema_version,
)
