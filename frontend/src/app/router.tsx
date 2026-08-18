import { createBrowserRouter } from 'react-router-dom';
import { AppLayout } from '../layouts/AppLayout';
import { ProtectedRoute, RoleRoute } from '../auth/guards';
import { LoginPage } from '../pages/LoginPage';
import { NotFoundPage, ForbiddenPage } from '../pages/NotFoundPage';
import { DashboardPage } from '../features/dashboard/DashboardPage';
import { InvestigationsPage } from '../features/cases/pages/InvestigationsPage';
import { CreateInvestigationPage } from '../features/cases/pages/CreateInvestigationPage';
import { CaseDetailPage } from '../features/cases/pages/CaseDetailPage';

import { AdminPage } from '../features/admin/pages/AdminPage';

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/',
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppLayout />,
        children: [
          // Dashboard (real data)
          {
            index: true,
            element: <DashboardPage />,
          },
          // Investigations (Case Management vertical slice)
          {
            path: 'investigations',
            element: <InvestigationsPage />,
          },
          {
            path: 'investigations/new',
            element: <CreateInvestigationPage />,
          },
          {
            path: 'investigations/:caseId',
            element: <CaseDetailPage />,
          },
          // Admin
          {
            path: 'admin',
            element: <RoleRoute allowedRoles={['administrator']} />,
            children: [
              {
                index: true,
                element: <AdminPage />,
              },
            ],
          },
          // Error pages
          {
            path: '403',
            element: <ForbiddenPage />,
          },
          {
            path: '*',
            element: <NotFoundPage />,
          },
        ],
      },
    ],
  },
]);
