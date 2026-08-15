import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Navbar } from "./components/Navbar";
import { Landing } from "./pages/Landing";
import { Dashboard } from "./pages/Dashboard";
import { History } from "./pages/History";
import { HistoryDetail } from "./pages/HistoryDetail";
import { useTheme } from "./hooks/useTheme";

export default function App() {
  const { theme, toggle } = useTheme();

  return (
    <BrowserRouter>
      <div className="flex min-h-full flex-col">
        <Navbar theme={theme} onToggleTheme={toggle} />
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/history" element={<History />} />
          <Route path="/history/:runId" element={<HistoryDetail />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
