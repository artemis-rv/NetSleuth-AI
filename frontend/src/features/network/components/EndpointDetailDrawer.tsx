
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogClose } from '../../../components/ui/dialog';
import { useEndpointDetailQuery } from '../hooks';

import { ExpandedEndpointPanel } from './ExpandedEndpointPanel';

interface EndpointDetailDrawerProps {
  /** The IP address of the endpoint to display. */
  endpointIp: string;
  /** The case ID for fetching data. */
  caseId: string;
  /** Callback to close the drawer. */
  onClose: () => void;
}

/**
 * A drawer component that loads the full context for a network endpoint and renders
 * the {@link ExpandedEndpointPanel} UI.
 *
 * The drawer opens automatically when {@link endpointIp} is provided. It uses the
 * {@link useEndpointDetailQuery} hook to fetch the detailed data from the backend.
 * When the query is loading, a spinner is shown. Errors are displayed inline.
 */
export function EndpointDetailDrawer({ caseId, endpointIp, onClose }: EndpointDetailDrawerProps) {
  const { data, isLoading, isError, error } = useEndpointDetailQuery(
    caseId,
    endpointIp
  );

  return (
    <Dialog open={true} onOpenChange={(open: boolean) => !open && onClose()}>
      <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Endpoint Detail – {endpointIp}</DialogTitle>
          <DialogClose />
        </DialogHeader>
        {isLoading && (
          <div className="flex items-center justify-center py-8">
            <div className="loader animate-spin rounded-full border-4 border-primary/20 border-t-primary h-8 w-8" />
          </div>
        )}
        {isError && (
          <div className="p-4 text-sm text-red-500 bg-red-50 rounded">
            Failed to load endpoint details: {(error as Error)?.message}
          </div>
        )}
        {data && (
          <ExpandedEndpointPanel
            endpoint={data}
            onSelectFlow={() => {}}
            onSelectFinding={() => {}}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
