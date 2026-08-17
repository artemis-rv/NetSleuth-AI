import json
import jsonschema
from pathlib import Path
from typing import Dict, Any

CONTRACTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "docs" / "contracts"

class ContractValidator:
    def __init__(self):
        self.schemas = {}
        self._load_schemas()

    def _load_schemas(self):
        if not CONTRACTS_DIR.exists():
            return
        for schema_file in CONTRACTS_DIR.glob("*-v*.json"):
            with open(schema_file, 'r', encoding='utf-8') as f:
                schema = json.load(f)
                self.schemas[schema_file.name] = schema

    def validate(self, schema_name: str, instance: Dict[str, Any]):
        schema = self.schemas.get(schema_name)
        if not schema:
            raise ValueError(f"Schema {schema_name} not found.")
        jsonschema.validate(
            instance=instance, 
            schema=schema, 
            format_checker=jsonschema.FormatChecker()
        )
