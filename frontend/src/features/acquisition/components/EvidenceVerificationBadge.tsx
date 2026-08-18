import { Badge } from '../../../components/ui/Badge';
import { ShieldAlert, ShieldCheck, Clock } from 'lucide-react';
import type { EvidenceResponse } from '../types';

export function EvidenceVerificationBadge({ status }: { status: EvidenceResponse['integrity_status'] }) {
  switch (status) {
    case 'verified':
      return (
        <Badge variant="success" className="gap-1.5 px-2 py-1">
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
          Verified
        </Badge>
      );
    case 'mismatch':
      return (
        <Badge variant="danger" className="gap-1.5 px-2 py-1">
          <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
          Hash Mismatch
        </Badge>
      );
    case 'error':
      return (
        <Badge variant="danger" className="gap-1.5 px-2 py-1">
          <ShieldAlert className="h-3.5 w-3.5" aria-hidden="true" />
          Verification Error
        </Badge>
      );
    case 'pending':
    default:
      return (
        <Badge variant="info" className="gap-1.5 px-2 py-1">
          <Clock className="h-3.5 w-3.5" aria-hidden="true" />
          Pending Verification
        </Badge>
      );
  }
}
