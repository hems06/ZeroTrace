import { useState } from "react";
import OperatorBar from "./components/OperatorBar";
import AuditLog from "./pages/AuditLog";
import Certificates from "./pages/Certificates";
import Dashboard from "./pages/Dashboard";
import Sanitize from "./pages/Sanitize";

type Tab = "dashboard" | "sanitize" | "certificates" | "audit";

const TABS: { key: Tab; label: string }[] = [
  { key: "dashboard", label: "Dashboard" },
  { key: "sanitize", label: "Sanitize" },
  { key: "certificates", label: "Certificates" },
  { key: "audit", label: "Audit Log" },
];

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="border-b border-slate-800 bg-gradient-to-r from-trust-900 to-slate-950">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <div className="flex items-center gap-2">
              <div className="h-8 w-8 rounded-lg bg-trust-600" />
              <div>
                <h1 className="text-lg font-bold text-white">ZeroTrace</h1>
                <p className="text-xs text-slate-400">
                  Secure Data Wiping for Trustworthy IT Asset Recycling
                </p>
              </div>
            </div>
          </div>
          <OperatorBar />
        </div>
        <nav className="mx-auto flex max-w-6xl gap-1 px-6">
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`rounded-t-md px-4 py-2 text-sm font-medium transition ${
                tab === t.key
                  ? "bg-slate-900 text-trust-600"
                  : "text-slate-400 hover:bg-slate-900/50 hover:text-slate-200"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </header>

      <main className="mx-auto max-w-6xl px-6 py-6">
        {tab === "dashboard" && <Dashboard />}
        {tab === "sanitize" && <Sanitize />}
        {tab === "certificates" && <Certificates />}
        {tab === "audit" && <AuditLog />}
      </main>

      <footer className="mx-auto max-w-6xl px-6 py-6 text-center text-xs text-slate-600">
        ZeroTrace — Secure Data Wiping for Trustworthy IT Asset Recycling. Physical-device sanitization
        requires Administrator (Windows) or root (Linux) privileges.
      </footer>
    </div>
  );
}
