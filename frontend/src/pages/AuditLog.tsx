import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AuditChainStatus, AuditEvent } from "../types/api";

export default function AuditLog() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [chain, setChain] = useState<AuditChainStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    api.listAuditEvents().then(setEvents).catch((e) => setError(e.message));
    api.auditChainStatus().then(setChain).catch((e) => setError(e.message));
  };

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Tamper-evident audit log</h2>
        <button onClick={load} className="text-xs text-trust-600 hover:underline">
          Re-verify chain
        </button>
      </div>

      {error && <div className="rounded bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</div>}

      {chain && (
        <div
          className={`rounded-lg border p-3 text-sm ${
            chain.intact ? "border-emerald-800 bg-emerald-950/30 text-emerald-200" : "border-rose-800 bg-rose-950/30 text-rose-200"
          }`}
        >
          <div className="font-semibold">
            Chain {chain.intact ? "intact" : "TAMPERING DETECTED"} — {chain.total_events} event(s) recorded
            {chain.first_invalid_seq !== null && ` (first break at seq #${chain.first_invalid_seq})`}
          </div>
          <div className="mt-1 text-xs opacity-80">{chain.limitation}</div>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-slate-900/60 text-left uppercase text-slate-500">
              <th className="px-3 py-2">Seq</th>
              <th className="px-3 py-2">Event</th>
              <th className="px-3 py-2">Operation</th>
              <th className="px-3 py-2">Timestamp</th>
              <th className="px-3 py-2">Entry hash</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.seq} className="border-t border-slate-800/60 bg-slate-900/30">
                <td className="px-3 py-2 text-slate-500">{e.seq}</td>
                <td className="px-3 py-2 font-medium text-slate-200">{e.event_type}</td>
                <td className="px-3 py-2 text-slate-400">{e.operation_id ?? "—"}</td>
                <td className="px-3 py-2 text-slate-500">{new Date(e.timestamp).toLocaleString()}</td>
                <td className="px-3 py-2 font-mono text-slate-600">{e.entry_hash.slice(0, 16)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && <div className="p-6 text-center text-sm text-slate-500">No audit events yet.</div>}
      </div>
    </div>
  );
}
