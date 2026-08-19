import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/layout/Sidebar';

export function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-background overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Topbar or breadcrumb placeholder could go here */}
        <div className="flex-1 overflow-auto p-6">
          <div className="mx-auto max-w-7xl">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
