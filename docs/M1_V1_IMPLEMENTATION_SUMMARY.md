# Master Walkthrough — M2 Analysis Engine (All Phases Complete)

The **M2 Analysis Engine** implementation is **100% Complete** across all 9 design phases. M2 transforms raw M1 `NetworkIntelligencePackage` objects into immutable, evidence-backed `FindingsPackage` objects consumable downstream by M3 (Correlation & Investigation).

---

## Architecture Overview

```
                      NetworkIntelligencePackage (M1)
                                   │
                                   ▼
                 Feature Extraction & Pipeline (M2 Phase 3-4)
                                   │
                                   ▼
                             FeatureVector
                                   │
           ┌───────────────────────┴───────────────────────┐
           ▼                                               ▼
Isolation Forest Baseline (Phase 5)            Random Forest Classifier (Phase 6)
   (Unsupervised Anomaly Score)                  (6-Class Activity Probabilities)
           │                                               │
           └───────────────────────┬───────────────────────┘
                                   ▼
                    Analysis Decision Engine (Phase 7)
                    (Risk Scoring & Decision Matrix)
                                   │
                                   ▼
                      Findings Generator (Phase 8)
                (Evidence Attribution & Rationale Generation)
                                   │
                                   ▼
                         FindingsPackage (M2 Output)
                                   │
                                   ▼
                     M3 Correlation & Investigation
```

---

## Complete Phase-by-Phase Breakdown

### Phase 1: Canonical Contracts & Types
- **Location**: `backend/app/contracts/analysis.py`
- **Key Artifacts**: `ActivityClass` (6-class taxonomy), `FeatureValue`, `FeatureVector`, `AnomalyResult`, `ClassificationResult`, `EvidenceReference`, `Finding`, `FindingsPackage`.
- **Constraint Enforcement**: Strictly forbids MITRE ATT&CK IDs, tactic names, attack chains, or threat intelligence in M2 (M3 responsibility).

---

### Phase 2: Canonical Label Normalization & Dataset Loader
- **Location**: `backend/app/engines/analysis/dataset/`
- **Key Modules**: `loader.py`, `labels.py`, `cleaner.py`.
- **Temporal Split Rules**:
  - **TRAIN**: Monday + Tuesday + Wednesday
  - **VALIDATION**: Thursday (Threshold & Hyperparameter Tuning)
  - **FINAL TEST**: Friday (Unseen Final Evaluation)
- **Label Integrity**: Uncertain labels (`Heartbleed`, unknown strings) map to `UNMAPPED` and are explicitly excluded from model training—never silently converted to `BENIGN`.

---

### Phase 3 & 4: Feature Extraction & Engineering Pipeline
- **Location**: `backend/app/engines/analysis/features/`
- **Key Modules**: `extractor.py`, `pipeline.py`, `transformer.py`, `validation.py`.
- **Features Extracted**: Flow statistics, DNS query/error distributions, HTTP method/uri entropy, TLS version entropy/cardinality, temporal flow rates, and active durations.
- **Safety Checks**: Enforces `_FORBIDDEN_DIMENSION_NAMES` to guarantee zero raw identifier leakage (`src_ip`, `dst_ip`, `zeek_uid`, `flow_id`).

---

### Phase 5: Unsupervised Anomaly Detection Baseline
- **Location**: `backend/app/engines/analysis/models/anomaly/`
- **Key Modules**: `isolation_forest.py`, `predictor.py`, `threshold.py`, `model_artifact.py`.
- **Model**: `IsolationForestAnomalyModel` trained deterministically (`random_state=42`) on benign baseline traffic.
- **Score Calibration**: Maps raw sklearn scores into calibrated deviation scores bounded in `[0.0, 1.0]`.

---

### Phase 6: Supervised Activity Classification
- **Location**: `backend/app/engines/analysis/models/classification/`
- **Key Modules**: `random_forest.py`, `predictor.py`, `label_map.py`, `model_artifact.py`.
- **Model**: `RandomForestActivityModel` (`class_weight='balanced'`, `n_estimators=100`).
- **Full Taxonomy Preservation**: Preserves the complete 6-class probability distribution across all `ActivityClass` members (`BENIGN`, `C2_MALWARE_COMMUNICATION`, `DNS_ANOMALY_TUNNELING`, `SCANNING_RECONNAISSANCE`, `POSSIBLE_EXFILTRATION`, `SUSPICIOUS_WEB_ACTIVITY`), setting `0.0` for missing/unobserved training classes.

---

### Phase 7: Analysis Decision Engine
- **Location**: `backend/app/engines/analysis/decision/`
- **Key Modules**: `engine.py`, `risk.py`, `confidence.py`, `result.py`.
- **Decision States**:
  - `BENIGN`: Baseline behavior.
  - `ANOMALOUS`: Elevated anomaly score + low classification confidence (unknown behavioral pattern; avoids false certainty).
  - `SUSPICIOUS_ACTIVITY`: Non-benign activity with moderate confidence/risk.
  - `HIGH_CONFIDENCE_ACTIVITY`: Non-benign activity with high confidence (>=0.75) and high risk/anomaly.
- **Deterministic Risk Engine**: Calculates `risk_score` combining anomaly magnitude, activity severity weights, classification confidence, evidence volume, and temporal persistence (`risk_score != anomaly_score`).

---

### Phase 8: Evidence Attribution & FindingsPackage Generation
- **Location**: `backend/app/engines/analysis/findings/`
- **Key Modules**: `generator.py`, `builder.py`, `attribution.py`.
- **Feature-to-Evidence Attribution**: Maps high-contributing numerical features to real M1 `flow_ids`, `event_ids`, and `artifact_ids` present in the source package.
- **No Evidence Fabrication**: Asserts all referenced IDs exist in the source package (raises `FabricatedEvidenceError` otherwise).
- **Measurable Explanations**: Generates feature rationales without MITRE IDs (e.g. *"high unique destination count (30), elevated connection rate (45/s)"*).

---

### Phase 9: Evaluation, Threshold Tuning, Model Registry, & Main Pipeline Entry Point
- **Location**: `backend/app/engines/analysis/evaluation/` & `backend/app/engines/analysis/engine.py`
- **Key Modules**: `metrics.py`, `threshold_optimizer.py`, `model_registry.py`, `evaluator.py`, `reports.py`, `engine.py`.
- **Main Production Interface**:
  ```python
  from backend.app.engines.analysis import M2AnalysisEngine

  engine = M2AnalysisEngine.from_directory("backend/app/engines/analysis/artifacts")
  findings_package = engine.analyze(network_intelligence_package)
  ```
- **Persisted Production Artifacts** in `backend/app/engines/analysis/artifacts/`:
  - `anomaly_model.json`
  - `isolation_forest.pkl`
  - `activity_classifier.json`
  - `activity_classifier.pkl`
  - `model_registry.json`

---

## Verification Summary

All **74 unit & integration tests** pass 100% across the codebase:

```
============================= test session starts =============================
platform win32 -- Python 3.13.5, pytest-9.1.1, pluggy-1.6.0
rootdir: D:\kanad\NetSleuth-AI

backend\tests\unit\test_m2_phase2_dataset.py ..................          [ 24%]
backend\tests\unit\test_m2_phase3_features.py ..............             [ 43%]
backend\tests\unit\test_m2_phase6_classification.py ..................   [ 67%]
backend\tests\unit\test_m2_phase7_decision.py .......                    [ 77%]
backend\tests\unit\test_m2_phase8_findings.py .......                    [ 86%]
backend\tests\unit\test_m2_phase9_evaluation.py .....                    [ 93%]
backend\tests\integration\test_m2_e2e_pipeline.py .....                  [100%]

===================== 74 passed in 13.38s =====================
```

M2 is complete, reproducible, evidence-backed, and ready for **M3 Correlation & Investigation**.
