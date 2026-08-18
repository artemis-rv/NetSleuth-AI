import { CreateCaseForm } from '../components/CreateCaseForm';
import { Card, CardContent } from '../../../components/ui/Card';
import { Link } from 'react-router-dom';
import { ChevronLeft } from 'lucide-react';

export function CreateInvestigationPage() {
  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-6">
        <Link
          to="/investigations"
          className="inline-flex items-center text-sm text-muted hover:text-primary transition-colors"
        >
          <ChevronLeft className="h-4 w-4 mr-1" aria-hidden="true" />
          Back to Investigations
        </Link>
      </div>

      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight text-primary">New Investigation</h1>
        <p className="text-sm text-muted mt-1">
          Define the case identity and triggering event before beginning analysis.
        </p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <CreateCaseForm />
        </CardContent>
      </Card>
    </div>
  );
}
