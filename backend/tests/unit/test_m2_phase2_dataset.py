"""
test_m2_phase2_dataset.py
-------------------------
M2 Phase 2 dataset module tests.

Validates the CICIDS2017 label normalization, data cleaning, split mapping,
and schema integration logic.
"""

import math
import os
import tempfile
import unittest
from pathlib import Path

from backend.app.contracts.analysis import ActivityClass
from backend.app.engines.analysis.dataset.cleaner import clean_row
from backend.app.engines.analysis.dataset.errors import (
    DatasetCleaningError,
    DatasetFileNotFoundError,
)
from backend.app.engines.analysis.dataset.labels import UNMAPPED, normalize_label
from backend.app.engines.analysis.dataset.loader import determine_split, load_dataset_file
from backend.app.contracts.feature_schema import FeatureName


class TestDatasetLabels(unittest.TestCase):
    def test_benign_mapping(self):
        self.assertEqual(normalize_label("BENIGN"), ActivityClass.BENIGN)
        self.assertEqual(normalize_label(" BENIGN "), ActivityClass.BENIGN)

    def test_scanning_mapping(self):
        self.assertEqual(normalize_label("FTP-Patator"), ActivityClass.SCANNING_RECONNAISSANCE)
        self.assertEqual(normalize_label("Portscan"), ActivityClass.SCANNING_RECONNAISSANCE)

    def test_c2_mapping(self):
        self.assertEqual(normalize_label("DoS GoldenEye"), ActivityClass.C2_MALWARE_COMMUNICATION)
        self.assertEqual(normalize_label("Botnet"), ActivityClass.C2_MALWARE_COMMUNICATION)

    def test_exfiltration_mapping(self):
        self.assertEqual(normalize_label("Infiltration"), ActivityClass.POSSIBLE_EXFILTRATION)

    def test_web_attack_mapping(self):
        self.assertEqual(normalize_label("Web Attack - XSS"), ActivityClass.SUSPICIOUS_WEB_ACTIVITY)
        self.assertEqual(normalize_label("Web Attack - SQL Injection"), ActivityClass.SUSPICIOUS_WEB_ACTIVITY)

    def test_unknown_label_is_unmapped(self):
        self.assertEqual(normalize_label("Heartbleed"), UNMAPPED)
        self.assertEqual(normalize_label("Completely Unknown Attack"), UNMAPPED)


class TestDatasetCleaner(unittest.TestCase):
    def test_valid_row_cleans_successfully(self):
        raw = {
            "Total Fwd Packet": "5",
            "Flow Duration": "100",
            " Label": "BENIGN"
        }
        features, label, h = clean_row(raw)
        self.assertEqual(label, "BENIGN")
        self.assertEqual(features["Total Fwd Packet"], 5.0)
        self.assertEqual(features["Flow Duration"], 100.0)
        self.assertIsInstance(h, str)

    def test_nan_values_rejected(self):
        raw = {
            "Total Fwd Packet": "NaN",
            "Label": "BENIGN"
        }
        with self.assertRaises(DatasetCleaningError):
            clean_row(raw)

    def test_inf_values_rejected(self):
        raw = {
            "Total Fwd Packet": "Infinity",
            "Label": "BENIGN"
        }
        with self.assertRaises(DatasetCleaningError):
            clean_row(raw)

    def test_missing_label_rejected(self):
        raw = {
            "Total Fwd Packet": "5",
            # missing label
        }
        with self.assertRaises(DatasetCleaningError):
            clean_row(raw)

    def test_duplicate_row_hashes_match(self):
        raw1 = {"Total Fwd Packet": "5", "Flow Duration": "100", "Label": "BENIGN"}
        raw2 = {"Total Fwd Packet": "  5.0 ", "Flow Duration": "100", " Label": " BENIGN"}
        _, _, h1 = clean_row(raw1)
        _, _, h2 = clean_row(raw2)
        self.assertEqual(h1, h2)

    def test_ignored_columns(self):
        raw = {
            "Flow ID": "192.168.1.1-10.0.0.1-80-443-6",
            "Src IP": "192.168.1.1",
            "Total Fwd Packet": "5",
            "Label": "BENIGN"
        }
        features, _, _ = clean_row(raw)
        self.assertNotIn("Flow ID", features)
        self.assertNotIn("Src IP", features)
        self.assertIn("Total Fwd Packet", features)


class TestDatasetLoader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.monday_csv = Path(self.temp_dir.name) / "Monday-WorkingHours.csv"
        self.thursday_csv = Path(self.temp_dir.name) / "Thursday-WorkingHours.csv"
        
        # Create a dummy CSV for Monday (Train)
        with open(self.monday_csv, "w", encoding="utf-8") as f:
            f.write("Total Fwd Packet,Flow Duration,Label\n")
            f.write("10,1000,BENIGN\n")
            f.write("20,2000,FTP-Patator\n")
            f.write("NaN,3000,BENIGN\n") # Malformed
            f.write("10,1000,BENIGN\n") # Duplicate
            
        # Create a dummy CSV for Thursday (Validation)
        with open(self.thursday_csv, "w", encoding="utf-8") as f:
            f.write("Total Fwd Packet,Flow Duration,Label\n")
            f.write("1,100,Heartbleed\n")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_split_determination(self):
        self.assertEqual(determine_split("monday.csv"), "train")
        self.assertEqual(determine_split("Tuesday.CSV"), "train")
        self.assertEqual(determine_split("Wednesday.csv"), "train")
        self.assertEqual(determine_split("Thursday-Morning.csv"), "validation")
        self.assertEqual(determine_split("FRIDAY.csv"), "test")
        self.assertEqual(determine_split("unknown.csv"), "unknown")

    def test_load_dataset_file_success(self):
        batch = load_dataset_file(self.monday_csv)
        self.assertEqual(batch.split, "train")
        self.assertEqual(batch.rows_loaded, 4)
        self.assertEqual(batch.rows_rejected, 1) # the NaN row
        self.assertEqual(batch.rows_duplicated, 1) # the duplicate row
        self.assertEqual(len(batch.records), 2)
        
        # Class counts
        self.assertEqual(batch.class_counts[ActivityClass.BENIGN.value], 1)
        self.assertEqual(batch.class_counts[ActivityClass.SCANNING_RECONNAISSANCE.value], 1)

    def test_load_dataset_file_unmapped(self):
        batch = load_dataset_file(self.thursday_csv)
        self.assertEqual(batch.split, "validation")
        self.assertEqual(len(batch.records), 1)
        
        record = batch.records[0]
        self.assertTrue(record.label.is_unmapped)
        self.assertIsNone(record.label.activity_class)
        self.assertEqual(record.label.source_label, "Heartbleed")
        self.assertEqual(batch.class_counts[UNMAPPED], 1)

    def test_no_label_leakage_in_features(self):
        batch = load_dataset_file(self.monday_csv)
        record = batch.records[0]
        
        # The label should NOT be in the feature vector
        feature_names = record.feature_vector.feature_names()
        for fn in feature_names:
            self.assertNotIn("label", fn.lower())
            
        # The label should NOT be in the raw features dict either
        for k in record.raw_features.keys():
            self.assertNotIn("label", k.lower())
            
    def test_feature_mapping_schema(self):
        batch = load_dataset_file(self.monday_csv)
        record = batch.records[0]
        
        # We mapped "Total Fwd Packet" -> FLOW_TOTAL_PACKETS
        # We mapped "Flow Duration" -> FLOW_MEAN_DURATION
        mapped_names = record.feature_vector.feature_names()
        self.assertIn(FeatureName.FLOW_TOTAL_PACKETS.value, mapped_names)
        self.assertIn(FeatureName.FLOW_MEAN_DURATION.value, mapped_names)

    def test_file_not_found(self):
        with self.assertRaises(DatasetFileNotFoundError):
            load_dataset_file("nonexistent.csv")

if __name__ == "__main__":
    unittest.main()
