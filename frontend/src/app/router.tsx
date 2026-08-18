import { createBrowserRouter } from 'react-router-dom';
import { AppLayout } from '../layouts/AppLayout';
import { ProtectedRoute, RoleRoute } from '../auth/guards';
import { LoginPage } from '../pages/LoginPage';
import { NotFoundPage, ForbiddenPage, DashboardPlaceholder } from '../pages/NotFoundPage';

export const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />
  },
  {
    path: '/',
    element: <ProtectedRoute />,
    children: [
      {
        element: <AppLayout />,
        children: [
          {
            index: true,
            element: <DashboardPlaceholder />
          },
          {
            path: 'cases',
            element: <DashboardPlaceholder />
          },
          {
            path: 'investigation',
            element: <DashboardPlaceholder />
          },
          {
            path: 'network',
            element: <DashboardPlaceholder />
          },
          {
            path: 'timeline',
            element: <DashboardPlaceholder />
          },
          {
            path: 'evidence',
            element: <DashboardPlaceholder />
          },
          {
            path: 'reports',
            element: <DashboardPlaceholder />
          },
          {
            path: 'admin',
            element: <RoleRoute allowedRoles={['administrator']} />,
            children: [
              {
                index: true,
                element: <DashboardPlaceholder />
              }
            ]
          },
          {
            path: '403',
            element: <ForbiddenPage />
          },
          {
            path: '*',
            element: <NotFoundPage />
          }
        ]
      }
    ]
  }
]);
