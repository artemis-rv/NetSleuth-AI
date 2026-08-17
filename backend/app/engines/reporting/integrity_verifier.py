import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from backend.app.shared.contract_validation import ContractValidator

SUPPORTED_HASH_ALGORITHMS = {"SHA-256", "SHA-512", "MD5"}
CANONICAL_EVIDENCE_TYPES = {
    "pcap", "flow", "session", "dns", "http", "tls", "artifact", "log", "finding"
}

class IntegrityVerifier:
    """
    M4 Integrity Verifier component.
    Calculates cryptographic hashes of evidence bytes, compares against expected upstream hashes,
    and returns contract-compliant verification result objects.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def calculate_hash(self, evidence_bytes: bytes, algorithm: str) -> str:
        """
        Derives cryptographic digest from raw evidence bytes.
        Does not mutate evidence_bytes.
        """
        if not isinstance(evidence_bytes, (bytes, bytearray)):
            raise ValueError("Evidence bytes must be a bytes or bytearray instance.")

        alg_upper = algorithm.upper() if algorithm else ""
        if alg_upper == "SHA-256":
            return hashlib.sha256(evidence_bytes).hexdigest()
        elif alg_upper == "SHA-512":
            return hashlib.sha512(evidence_bytes).hexdigest()
        elif alg_upper == "MD5":
            return hashlib.md5(evidence_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported or missing hash algorithm: {algorithm}")

    def verify(
        self,
        metadata: Dict[str, Any],
        evidence_bytes: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """
        Verifies evidence integrity against metadata and optional evidence bytes.

        :param metadata: Dict containing evidence_id, case_id, evidence_type, expected_hash, etc.
        :param evidence_bytes: Raw bytes of the evidence payload.
        :return: Dict adhering to docs/contracts/evidence-integrity-v1.json
        """
        if not isinstance(metadata, dict):
            raise ValueError("Metadata must be a dictionary.")

        # Required contract metadata validation
        evidence_id = metadata.get("evidence_id")
        case_id = metadata.get("case_id")
        evidence_type = metadata.get("evidence_type")

        if not evidence_id or not isinstance(evidence_id, str):
            raise ValueError("Metadata missing required 'evidence_id'.")
        if not case_id or not isinstance(case_id, str):
            raise ValueError("Metadata missing required 'case_id'.")
        if not evidence_type or evidence_type not in CANONICAL_EVIDENCE_TYPES:
            raise ValueError(f"Metadata missing or invalid 'evidence_type': {evidence_type}")

        source_id = metadata.get("source_id")
        expected_hash = metadata.get("expected_hash")
        raw_algo = metadata.get("hash_algorithm")

        # 1. Validate hash algorithm compliance with contract enum ['SHA-256', 'SHA-512', 'MD5', null]
        if raw_algo in SUPPORTED_HASH_ALGORITHMS:
            hash_algorithm = raw_algo
        else:
            # Unsupported or missing algorithm -> None
            hash_algorithm = None

        # 2. Determine calculated_hash and verification_status
        calculated_hash: Optional[str] = None
        verification_status = "unverified"

        if hash_algorithm and evidence_bytes is not None:
            if isinstance(evidence_bytes, (bytes, bytearray)):
                calculated_hash = self.calculate_hash(evidence_bytes, hash_algorithm)
                if expected_hash and isinstance(expected_hash, str):
                    if calculated_hash.lower() == expected_hash.lower():
                        verification_status = "verified"
                    else:
                        verification_status = "mismatch"
                else:
                    # Expected hash unavailable
                    verification_status = "unverified"
            else:
                raise ValueError("Evidence bytes must be a bytes instance.")
        else:
            # Missing bytes or unsupported algorithm -> unverified
            verification_status = "unverified"

        # 3. Timestamp generation (verified_at generated ONLY upon execution)
        verified_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 4. Assemble contract-compliant result payload
        result: Dict[str, Any] = {
            "schema_version": "evidence-integrity-v1",
            "evidence_id": evidence_id,
            "case_id": case_id,
            "evidence_type": evidence_type,
            "source_id": source_id,
            "expected_hash": expected_hash,
            "calculated_hash": calculated_hash,
            "hash_algorithm": hash_algorithm,
            "verification_status": verification_status,
            "verified_at": verified_at
        }

        if metadata.get("collected_at") is not None:
            result["collected_at"] = metadata["collected_at"]
        if metadata.get("ingested_at") is not None:
            result["ingested_at"] = metadata["ingested_at"]
        if metadata.get("provenance") is not None:
            result["provenance"] = metadata["provenance"]
        if metadata.get("chain_of_custody") is not None:
            result["chain_of_custody"] = metadata["chain_of_custody"]

        # 5. Enforce strict schema validation
        self.validator.validate("evidence-integrity-v1.json", result)

        return result
