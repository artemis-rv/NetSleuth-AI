import { Outlet } from 'react-router-dom';
import { Sidebar } from '../components/layout/Sidebar';

export function AppLayout() {
  return (
    <div className="flex h-screen w-full bg-background overflow-hidden">
      <Sidebar />
      <main className="flex-1 flex flex-col h-full overflow-hidden min-h-0">
        <div className="flex-1 overflow-hidden p-4 md:p-6 flex flex-col min-h-0">
          <div className="mx-auto max-w-7xl w-full h-full flex flex-col min-h-0">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
