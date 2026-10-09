import { useEffect, useState } from "react";
import { api } from "../api/client";
import StatCard from "../components/StatCard";
import StatusBadge from "../components/StatusBadge";
import type { DashboardSummary } from "../types/api";

export default function Dashboard() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    api
      .dashboardSummary()
      .then(setSummary)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  if (error) {
    return <div className="rounded-lg border border-rose-800 bg-rose-950/40 p-4 text-rose-300">Failed to load dashboard: {error}</div>;
  }
  if (!summary) {
    return <div className="text-slate-500">Loading live application state…</div>;
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Total operations" value={summary.total_operations} />
        <StatCard label="Verified" value={summary.verified_count} accent="text-emerald-400" />
        <StatCard label="Failed" value={summary.failed_count} accent="text-rose-400" />
        <StatCard label="Inconclusive" value={summary.inconclusive_count} accent="text-amber-400" />
      </div>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Image-based tests" value={summary.image_based_operations} />
        <StatCard label="Demonstration runs" value={summary.demo_operations} />
        <StatCard label="Physical device attempts" value={summary.physical_operations} />
        <StatCard label="Certificates issued" value={summary.total_certificates} />
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-semibold text-slate-200">
          Recent sanitization activity
        </div>
        {summary.recent_operations.length === 0 ? (
          <div className="p-6 text-center text-sm text-slate-500">
            No operations yet. Start one from the "Sanitize" tab — image-based testing works without a
            physical USB device.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase text-slate-500">
                <th className="px-4 py-2">Target</th>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Verification</th>
                <th className="px-4 py-2">Created</th>
              </tr>
            </thead>
            <tbody>
              {summary.recent_operations.map((op) => (
                <tr key={op.id} className="border-t border-slate-800/60">
                  <td className="px-4 py-2 text-slate-300">{op.target_label}</td>
                  <td className="px-4 py-2 text-slate-400">
                    {op.target_type}
                    {op.simulation_only && <span className="ml-1 text-indigo-400">(sim)</span>}
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={op.status} />
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={op.verification_status} />
                  </td>
                  <td className="px-4 py-2 text-slate-500">{new Date(op.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-xs text-slate-500">
        Total audit events recorded: <span className="text-slate-300">{summary.total_audit_events}</span>. Visit
        the Audit Log tab to inspect the hash-linked event chain.
      </div>
    </div>
  );
}
