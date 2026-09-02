import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { Detectors } from "./pages/Detectors";
import { Login } from "./pages/Login";
import { ProjectDetail } from "./pages/ProjectDetail";
import { Projects } from "./pages/Projects";
import { ScanDetail } from "./pages/ScanDetail";
import { Spinner } from "./components/common";
import { useAuth } from "./hooks/useAuth";

export default function App() {
  const { user, loading, logout } = useAuth();

  if (loading) {
    return (
      <div className="auth-shell">
        <Spinner label="Starting SupplyGuard…" />
      </div>
    );
  }
  if (!user) return <Login />;

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">
          Supply<span>Guard</span>
        </span>
        <nav>
          <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>
            Projects
          </NavLink>
          <NavLink to="/detectors" className={({ isActive }) => (isActive ? "active" : "")}>
            Detectors
          </NavLink>
        </nav>
        <div className="spacer" />
        <span style={{ color: "var(--text-dim)", fontSize: 13 }}>{user.email}</span>
        <button onClick={logout}>Sign out</button>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<Projects />} />
          <Route path="/projects/:projectId" element={<ProjectDetail />} />
          <Route path="/scans/:scanId" element={<ScanDetail />} />
          <Route path="/detectors" element={<Detectors />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
