import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AnimatePresence } from "motion/react";
import Layout from "./components/layout/Layout";
import Dashboard from "./pages/Dashboard";
import LiveAlerts from "./pages/LiveAlerts";
import GraphExplorer from "./pages/GraphExplorer";
import CampaignViewer from "./pages/CampaignViewer";
import ThreatLookup from "./pages/ThreatLookup";
import AiAssistant from "./pages/AiAssistant";
import PageWrapper from "./components/layout/PageWrapper";

function AnimatedRoutes() {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <Routes location={location} {...{ key: location.pathname }}>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<PageWrapper><Dashboard /></PageWrapper>} />
          <Route path="alerts" element={<PageWrapper><LiveAlerts /></PageWrapper>} />
          <Route path="campaigns" element={<PageWrapper><CampaignViewer /></PageWrapper>} />
          <Route path="graph" element={<PageWrapper><GraphExplorer /></PageWrapper>} />
          <Route path="lookup" element={<PageWrapper><ThreatLookup /></PageWrapper>} />
          <Route path="ai" element={<PageWrapper><AiAssistant /></PageWrapper>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </AnimatePresence>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AnimatedRoutes />
    </BrowserRouter>
  );
}
