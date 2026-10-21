import { useQuery } from '@tanstack/react-query';
import { api } from './api/client';
import { useUI } from './store/uiStore';
import { Sidebar } from './components/layout/Sidebar';
import { Topbar } from './components/layout/Topbar';
import { DashboardPage } from './pages/DashboardPage';
import { CasesPage } from './pages/CasesPage';
import { UploadPage } from './pages/UploadPage';
import { JobsPage } from './pages/JobsPage';
import { IocsPage } from './pages/IocsPage';
import { ReportsPage } from './pages/ReportsPage';
import { TimelinePage } from './pages/TimelinePage';
import { GraphPage } from './pages/GraphPage';
import { ArtifactsPage } from './pages/ArtifactsPage';
import { UsersPage } from './pages/UsersPage';
import { SettingsPage } from './pages/SettingsPage';

export default function App() {
  const tab = useUI((s) => s.tab);
  const me = useQuery({
    queryKey: ['me'],
    queryFn: api.me,
  });

  const pages: Record<string, React.ReactNode> = {
    overview: <DashboardPage />,
    cases: <CasesPage />,
    upload: <UploadPage />,
    jobs: <JobsPage />,
    iocs: <IocsPage />,
    reports: <ReportsPage />,
    timeline: <TimelinePage />,
    graph: <GraphPage />,
    artifacts: <ArtifactsPage />,
    users: <UsersPage />,
    settings: <SettingsPage />,
  };

  return (
    <div className="shell">
      <Sidebar admin={!!me.data?.is_admin} />
      <main>
        <Topbar user={me.data} />
        <section className="page">
          {pages[tab] || pages.overview}
        </section>
      </main>
    </div>
  );
}
