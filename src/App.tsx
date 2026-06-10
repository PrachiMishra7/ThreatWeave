import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";

// Temporary placeholder pages
const Placeholder = ({ title }: { title: string }) => (
  <div className="flex items-center justify-center h-full min-h-[400px]">
    <h2 className="text-2xl font-semibold text-slate-400">{title} Component (Coming Soon)</h2>
  </div>
);

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Placeholder title="Dashboard" />} />
          <Route path="alerts" element={<Placeholder title="Live Alerts" />} />
          <Route path="campaigns" element={<Placeholder title="Campaigns" />} />
          <Route path="graph" element={<Placeholder title="Graph Explorer" />} />
          <Route path="lookup" element={<Placeholder title="Threat Lookup" />} />
          <Route path="ai" element={<Placeholder title="AI Assistant" />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
