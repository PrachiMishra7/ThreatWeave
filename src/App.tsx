import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/layout/Layout";
import Dashboard from "./pages/Dashboard";
import LiveAlerts from "./pages/LiveAlerts";
import GraphExplorer from "./pages/GraphExplorer";
import CampaignViewer from "./pages/CampaignViewer";
import ThreatLookup from "./pages/ThreatLookup";
import AiAssistant from "./pages/AiAssistant";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="alerts" element={<LiveAlerts />} />
          <Route path="campaigns" element={<CampaignViewer />} />
          <Route path="graph" element={<GraphExplorer />} />
          <Route path="lookup" element={<ThreatLookup />} />
          <Route path="ai" element={<AiAssistant />} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
