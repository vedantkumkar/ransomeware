import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AppLayout } from '@/layouts/AppLayout';
import DashboardPage from '@/pages/DashboardPage';
import IncidentsPage from '@/pages/IncidentsPage';
import IncidentDetailPage from '@/pages/IncidentDetailPage';
import EndpointsPage from '@/pages/EndpointsPage';
import EvidencePage from '@/pages/EvidencePage';
import ActivityLogPage from '@/pages/ActivityLogPage';
import SettingsPage from '@/pages/SettingsPage';
import NotFoundPage from '@/pages/NotFoundPage';

export function App() {
  // import.meta.env.BASE_URL follows the Vite build base path: "/" locally,
  // "/<repo-name>/" on GitHub Pages — so routing works in both without changes.
  return (
    <BrowserRouter basename={import.meta.env.BASE_URL}>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/incidents/:id" element={<IncidentDetailPage />} />
          <Route path="/endpoints" element={<EndpointsPage />} />
          <Route path="/evidence" element={<EvidencePage />} />
          <Route path="/activity" element={<ActivityLogPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
