const STYLES: Record<string, string> = {
  verified: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
  completed: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
  Verified: "bg-emerald-900/40 text-emerald-300 border-emerald-700",
  failed: "bg-rose-900/40 text-rose-300 border-rose-700",
  Failed: "bg-rose-900/40 text-rose-300 border-rose-700",
  inconclusive: "bg-amber-900/40 text-amber-300 border-amber-700",
  Inconclusive: "bg-amber-900/40 text-amber-300 border-amber-700",
  not_run: "bg-slate-800 text-slate-400 border-slate-600",
  running: "bg-sky-900/40 text-sky-300 border-sky-700",
  pending: "bg-slate-800 text-slate-400 border-slate-600",
  blocked_safety_disabled: "bg-amber-900/40 text-amber-300 border-amber-700",
  blocked_not_implemented: "bg-amber-900/40 text-amber-300 border-amber-700",
  "Simulation Only": "bg-indigo-900/40 text-indigo-300 border-indigo-700",
};

export default function StatusBadge({ status }: { status: string }) {
  const style = STYLES[status] ?? "bg-slate-800 text-slate-300 border-slate-600";
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${style}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}
