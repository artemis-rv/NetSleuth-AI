# FE-2: Acquisition and Analysis Workflow

## Overview
The FE-2 module connects the React frontend (`FE-1` foundation) to the robust `APP-3` (Acquisition + Evidence) and `APP-4` (Analysis Job) backend REST API. It handles the secure upload, verification, and automated forensic processing of PCAP and PCAPNG evidence captures.

## Components

### 1. Acquisition Module (`src/features/acquisition`)
Responsible for managing network capture files securely.
- **AcquisitionSection**: Upload interface with a 1GB client-side limit, rendering metadata (size, format, hash, upload time).
- **EvidenceVerificationBadge**: Visual status for cryptographic integrity (`verified`, `mismatch`, `error`, `pending`).
- **Hooks & API**: Utilizes TanStack Query for caching and mutations (file upload via `FormData`, evidence verification).

### 2. Analysis Module (`src/features/analysis`)
Orchestrates the asynchronous parsing, correlation, and intelligence generation pipeline.
- **AnalysisSection**: Initiates jobs, lists previous runs, and renders an animated execution timeline.
- **Timeline rendering**: Visualizes stages (`QUEUED` -> `M1` -> `M2` -> `M3` -> `M4` -> `COMPLETED`), with real-time polling updates when a job is actively running or queued.
- **Hooks & API**: Queries the analysis status with dynamic polling via `refetchInterval`.

## Integration
Both modules have been seamlessly integrated into `CaseDetailPage.tsx` beneath the `Investigation Goals` panel, creating a chronological left-to-right user experience: Case context -> Upload Evidence -> Verify Integrity -> Execute Analysis -> (Future: Review Findings).

## Security & Reliability
- Uses `@tanstack/react-query` to ensure atomic state updates and prevent duplicate requests.
- Does not expose raw file byte streams to browser state, adhering to strict memory constraints.
- Shows sanitized error messages, never leaking sensitive stack traces to the user interface.
