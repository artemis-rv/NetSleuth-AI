"""
extractor.py
------------
M2 Phase 3 orchestrator for NetworkIntelligencePackage Feature Extraction.

Coordinates the specialized feature extractors and returns a fully
populated M2 FeatureVector.
"""

from __future__ import annotations

import logging
from uuid import uuid4

from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FeatureVector, FeatureValue
from app.engines.analysis.features.flow_features import extract_flow_features
from app.engines.analysis.features.dns_features import extract_dns_features
from app.engines.analysis.features.http_features import extract_http_features
from app.engines.analysis.features.tls_features import extract_tls_features
from app.engines.analysis.features.temporal_features import extract_temporal_features
from app.engines.analysis.features.distribution_features import extract_distribution_features

logger = logging.getLogger(__name__)


def extract_all_features(package: NetworkIntelligencePackage) -> FeatureVector:
    """Extract all deterministic intermediate behavioral features from a package.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        A deterministic M2 FeatureVector.
    """
    logger.debug("Extracting features for package: %s", package.acquisition_id)
    
    features: list[FeatureValue] = []
    
    # Delegate to specialized extractors
    features.extend(extract_flow_features(package))
    features.extend(extract_dns_features(package))
    features.extend(extract_http_features(package))
    features.extend(extract_tls_features(package))
    features.extend(extract_temporal_features(package))
    features.extend(extract_distribution_features(package))
    
    # Sort deterministically by feature name
    features.sort(key=lambda f: f.name)
    
    vector_id = f"FV-{uuid4().hex[:12].upper()}"
    
    return FeatureVector(
        vector_id=vector_id,
        acquisition_id=package.acquisition_id,
        features=features
    )
