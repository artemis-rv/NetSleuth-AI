import json
from copy import deepcopy
from typing import Dict, Any
from app.shared.contract_validation import ContractValidator

class ReportExporter:
    """
    M4 Report Exporter.
    Provides canonical, validated, deterministic JSON serialization of Report V1 contracts.
    Does NOT perform HTML/PDF rendering, database persistence, or investigative enrichment.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def export_json(self, report: Dict[str, Any], indent: int = 2) -> str:
        """
        Exports a validated Report V1 or Report V1.1 dictionary as a deterministic, formatted JSON string.

        :param report: Dict adhering to docs/contracts/report-v1.json or docs/contracts/report-v1.1.json
        :param indent: Integer indentation level for JSON formatting (default: 2)
        :return: Formatted UTF-8 JSON string representation.
        """
        if not isinstance(report, dict):
            raise ValueError("Report input must be a dictionary.")

        # 1. Input immutability
        report_copy = deepcopy(report)

        # 2. Version-aware contract validation
        schema_version = report_copy.get("schema_version")
        if schema_version == "report-v1":
            schema_file = "report-v1.json"
        elif schema_version == "report-v1.1":
            schema_file = "report-v1.1.json"
        elif schema_version == "report-v1.2":
            schema_file = "report-v1.2.json"
        elif schema_version == "report-v1.3":
            schema_file = "report-v1.3.json"
        else:
            raise ValueError(f"Unsupported or unknown report schema_version '{schema_version}'.")

        self.validator.validate(schema_file, report_copy)

        # 3. Deterministic JSON serialization with sorted keys and UTF-8 string support
        return json.dumps(report_copy, indent=indent, sort_keys=True, ensure_ascii=False)
