"""
http_features.py
----------------
Extracts M2 HTTP features from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import statistics

from app.contracts.network_intelligence import NetworkIntelligencePackage, HTTPData
from app.contracts.analysis import FeatureValue
from app.contracts.feature_schema import FeatureName


def extract_http_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate HTTP features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    http_events = [
        event for event in package.protocol_events 
        if event.protocol == "http" and isinstance(event.protocol_data, HTTPData)
    ]
    
    count = len(http_events)
    if count == 0:
        return _build_empty_http_features()
        
    unique_hosts = set()
    unique_uris = set()
    unique_methods = set()
    unique_user_agents = set()
    
    get_count = 0
    post_count = 0
    error_count = 0
    redirect_count = 0
    missing_ua_count = 0
    
    download_bytes = 0
    upload_bytes = 0
    
    uri_lengths = []
    
    for event in http_events:
        data: HTTPData = event.protocol_data
        
        if data.host:
            unique_hosts.add(data.host)
            
        if data.uri:
            unique_uris.add(data.uri)
            uri_lengths.append(len(data.uri))
            
        if data.method:
            method = data.method.upper()
            unique_methods.add(method)
            if method == "GET":
                get_count += 1
            elif method == "POST":
                post_count += 1
                
        if data.status_code:
            if 400 <= data.status_code < 600:
                error_count += 1
            elif 300 <= data.status_code < 400:
                redirect_count += 1
                
        if data.user_agent:
            unique_user_agents.add(data.user_agent)
        else:
            missing_ua_count += 1
            
        if data.request_body_len:
            upload_bytes += data.request_body_len
            
        if data.response_body_len:
            download_bytes += data.response_body_len

    mean_uri_len = statistics.mean(uri_lengths) if uri_lengths else None
    max_uri_len = max(uri_lengths) if uri_lengths else None
    
    get_ratio = get_count / count
    post_ratio = post_count / count
    error_ratio = error_count / count
    redirect_ratio = redirect_count / count
    missing_ua_ratio = missing_ua_count / count

    return [
        FeatureValue(name=FeatureName.HTTP_REQUEST_COUNT.value, value=float(count)),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_HOSTS.value, value=float(len(unique_hosts))),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_URIS.value, value=float(len(unique_uris))),
        FeatureValue(name=FeatureName.HTTP_METHOD_COUNT.value, value=float(len(unique_methods))),
        FeatureValue(name=FeatureName.HTTP_GET_RATIO.value, value=float(get_ratio)),
        FeatureValue(name=FeatureName.HTTP_POST_RATIO.value, value=float(post_ratio)),
        FeatureValue(name=FeatureName.HTTP_ERROR_STATUS_RATIO.value, value=float(error_ratio)),
        FeatureValue(name=FeatureName.HTTP_REDIRECT_RATIO.value, value=float(redirect_ratio)),
        FeatureValue(name=FeatureName.HTTP_DOWNLOAD_BYTES.value, value=float(download_bytes)),
        FeatureValue(name=FeatureName.HTTP_UPLOAD_BYTES.value, value=float(upload_bytes)),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_USER_AGENTS.value, value=float(len(unique_user_agents))),
        FeatureValue(name=FeatureName.HTTP_MISSING_USER_AGENT_RATIO.value, value=float(missing_ua_ratio)),
        FeatureValue(name=FeatureName.HTTP_URI_LENGTH_MEAN.value, value=mean_uri_len, present=mean_uri_len is not None),
        FeatureValue(name=FeatureName.HTTP_URI_LENGTH_MAX.value, value=max_uri_len, present=max_uri_len is not None),
    ]


def _build_empty_http_features() -> list[FeatureValue]:
    return [
        FeatureValue(name=FeatureName.HTTP_REQUEST_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_HOSTS.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_URIS.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_METHOD_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_GET_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_POST_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_ERROR_STATUS_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_REDIRECT_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_DOWNLOAD_BYTES.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_UPLOAD_BYTES.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_UNIQUE_USER_AGENTS.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_MISSING_USER_AGENT_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.HTTP_URI_LENGTH_MEAN.value, value=None, present=False),
        FeatureValue(name=FeatureName.HTTP_URI_LENGTH_MAX.value, value=None, present=False),
    ]
