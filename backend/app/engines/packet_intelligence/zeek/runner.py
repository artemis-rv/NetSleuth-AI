"""
backend/app/engines/packet_intelligence/zeek/runner.py
------------------------------------------------------
Zeek Runner Engine (Phase 3).

Orchestrates Docker-based offline Zeek execution on a validated PCAP/PCAPNG.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from app.contracts.network_intelligence import AcquisitionReference
from .errors import ZeekRunnerError, ZeekRunnerErrorCode
from .result import ZeekRunnerResult, ZeekRunnerStatus


class ZeekRunner:
    """Executes Zeek against a validated capture file using Docker."""

    def __init__(
        self,
        output_root: str | os.PathLike = "sample_data/zeek_output",
        allowed_evidence_roots: list[str | os.PathLike] | None = None,
        timeout_seconds: float = 300.0,
        zeek_image: str = "zeek/zeek:lts",
    ) -> None:
        """Initialize the Zeek Runner.

        Parameters:
            output_root: Root directory where isolated output folders are created.
            allowed_evidence_roots: Allowed directories for PCAP mounting.
                                    Prevents arbitrary host directory mounting.
            timeout_seconds: Maximum execution time for the Zeek process.
            zeek_image: Docker image to execute.
        """
        self.output_root = Path(output_root).resolve()
        self.timeout_seconds = timeout_seconds
        self.zeek_image = zeek_image

        # Default allowed roots: sample_data/evidence and system temp dir
        if allowed_evidence_roots is None:
            self.allowed_evidence_roots = [
                Path("sample_data/evidence").resolve(),
                Path(tempfile.gettempdir()).resolve(),
            ]
        else:
            self.allowed_evidence_roots = [
                Path(r).resolve() for r in allowed_evidence_roots
            ]

    def run(self, ref: AcquisitionReference) -> ZeekRunnerResult:
        """Run Zeek on the pcap referenced by `ref`.

        Parameters:
            ref: AcquisitionReference representing a validated capture.

        Returns:
            ZeekRunnerResult containing metadata and details of the run.

        Raises:
            ZeekRunnerError: on Docker, configuration, or environment failures.
        """
        # Step 1: Pre-flight checks (Docker executable & daemon availability)
        self._check_docker_env()

        # Step 2: Check Zeek image availability and obtain version
        zeek_version = self._get_zeek_version()

        # Step 3: Validate input path
        pcap_path = self._validate_input_path(ref.capture_reference)

        # Step 4: Prepare isolated output directory
        output_dir = self.output_root / ref.acquisition_id
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                f"Failed to create output directory {output_dir}: {exc}",
            ) from exc

        # Step 5: Execute Zeek via Docker
        evidence_dir = pcap_path.parent
        relative_pcap = pcap_path.name

        cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{evidence_dir}:/data/evidence:ro",
            "-v",
            f"{output_dir.resolve()}:/data/output",
            "--workdir",
            "/data/output",
            self.zeek_image,
            "zeek",
            "-r",
            f"/data/evidence/{relative_pcap}",
            "LogAscii::use_json=T",
        ]

        start_time = time.perf_counter()
        status = ZeekRunnerStatus.SUCCESS
        exit_code = 0
        stderr_tail = ""

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,
            )
            exit_code = res.returncode
            stderr_tail = "\n".join(res.stderr.splitlines()[-10:])

            if exit_code != 0:
                status = ZeekRunnerStatus.FAILED
                # Zeek runtime errors are captured here
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.ZEEK_NONZERO_EXIT,
                    f"Zeek process exited with non-zero code {exit_code}. Stderr: {res.stderr.strip()}",
                )

        except subprocess.TimeoutExpired as exc:
            status = ZeekRunnerStatus.TIMED_OUT
            stderr_tail = exc.stderr.decode("utf-8", errors="ignore") if exc.stderr else ""
            exit_code = None
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.TIMEOUT,
                f"Zeek execution timed out after {self.timeout_seconds} seconds.",
            ) from exc
        except subprocess.SubprocessError as exc:
            status = ZeekRunnerStatus.FAILED
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.DOCKER_PROCESS_FAILED,
                f"Subprocess call failed: {exc}",
            ) from exc

        finally:
            duration = time.perf_counter() - start_time

        # Step 6: Discover generated logs
        generated_logs = []
        if status == ZeekRunnerStatus.SUCCESS:
            try:
                for entry in output_dir.iterdir():
                    if entry.is_file():
                        generated_logs.append(entry.name)
            except OSError as exc:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.OUTPUT_DIR_ERROR,
                    f"Failed to list output directory contents: {exc}",
                ) from exc

        return ZeekRunnerResult(
            acquisition_id=ref.acquisition_id,
            status=status,
            output_directory=output_dir,
            generated_logs=sorted(generated_logs),
            exit_code=exit_code,
            execution_duration_s=round(duration, 3),
            zeek_image=self.zeek_image,
            zeek_version=zeek_version,
            stderr_tail=stderr_tail,
        )

    def _check_docker_env(self) -> None:
        """Verify Docker is installed and daemon is responsive."""
        if not shutil.which("docker"):
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.DOCKER_NOT_FOUND,
                "Docker executable not found in path.",
            )

        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=10,
                shell=False,
            )
            if res.returncode != 0:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.DOCKER_DAEMON_UNAVAILABLE,
                    f"Docker daemon is unresponsive: {res.stderr.decode('utf-8', errors='ignore').strip()}",
                )
        except subprocess.TimeoutExpired as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.TIMEOUT,
                "Timeout verifying Docker daemon connectivity.",
            ) from exc
        except Exception as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.DOCKER_DAEMON_UNAVAILABLE,
                f"Failed to communicate with Docker daemon: {exc}",
            ) from exc

    def _get_zeek_version(self) -> str:
        """Inspect/run image to retrieve Zeek version. Pulls the image if not present."""
        
        # Ensure the image is present locally
        try:
            subprocess.run(
                ["docker", "image", "inspect", self.zeek_image],
                capture_output=True,
                check=True,
                shell=False
            )
        except subprocess.CalledProcessError:
            # Pull the image if it does not exist locally
            try:
                subprocess.run(
                    ["docker", "pull", self.zeek_image],
                    capture_output=True,
                    timeout=300,
                    check=True,
                    shell=False
                )
            except subprocess.TimeoutExpired as exc:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.TIMEOUT,
                    f"Timeout pulling Zeek image {self.zeek_image}",
                ) from exc
            except subprocess.CalledProcessError as exc:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.IMAGE_UNAVAILABLE,
                    f"Failed to pull Zeek image {self.zeek_image}: {exc.stderr.decode('utf-8', errors='ignore').strip()}",
                ) from exc

        try:
            res = subprocess.run(
                ["docker", "run", "--rm", self.zeek_image, "zeek", "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                shell=False,
            )
            if res.returncode != 0:
                raise ZeekRunnerError(
                    ZeekRunnerErrorCode.IMAGE_UNAVAILABLE,
                    f"Zeek Docker image {self.zeek_image} failed version query: {res.stderr.strip()}",
                )
            version_line = res.stdout.strip()
            if "version" in version_line:
                return version_line.split("version")[-1].strip()
            return version_line
        except subprocess.TimeoutExpired as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.TIMEOUT,
                f"Timeout checking Zeek image version for {self.zeek_image}",
            ) from exc
        except Exception as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.IMAGE_UNAVAILABLE,
                f"Zeek image {self.zeek_image} is unavailable or failed to execute: {exc}",
            ) from exc

    def _validate_input_path(self, capture_reference: str) -> Path:
        """Verify the capture file exists and is within allowed roots."""
        try:
            resolved = Path(capture_reference).resolve()
        except (TypeError, ValueError) as exc:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.INVALID_INPUT_PATH,
                f"Invalid capture reference path: {capture_reference!r}",
            ) from exc

        if not resolved.exists():
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.CAPTURE_NOT_FOUND,
                f"Capture file not found: {resolved}",
            )

        # Path traversal prevention: resolve must start with one of the allowed roots
        is_allowed = False
        for root in self.allowed_evidence_roots:
            try:
                # Check if the resolved file path is sub-path of an allowed root
                resolved.relative_to(root)
                is_allowed = True
                break
            except ValueError:
                continue

        if not is_allowed:
            raise ZeekRunnerError(
                ZeekRunnerErrorCode.PATH_TRAVERSAL_DETECTED,
                f"Input path {resolved} is outside allowed evidence directories.",
            )

        return resolved
