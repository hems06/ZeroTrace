import { useEffect, useState } from "react";
import { api } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { Certificate, CertificateVerifyResult } from "../types/api";

export default function Certificates() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [verifyResults, setVerifyResults] = useState<Record<string, CertificateVerifyResult>>({});
  const [error, setError] = useState<string | null>(null);

  const load = () => api.listCertificates().then(setCerts).catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const verify = async (id: string) => {
    const result = await api.verifyCertificate(id);
    setVerifyResults((prev) => ({ ...prev, [id]: result }));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Certificate history</h2>
        <button onClick={load} className="text-xs text-trust-600 hover:underline">
          Refresh
        </button>
      </div>
      {error && <div className="rounded bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</div>}
      {certs.length === 0 ? (
        <div className="rounded border border-dashed border-slate-700 p-6 text-center text-sm text-slate-500">
          No certificates issued yet. Complete a sanitization operation in the "Sanitize" tab, then generate one.
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-slate-900/60 text-left text-xs uppercase text-slate-500">
                <th className="px-4 py-2">Certificate</th>
                <th className="px-4 py-2">Operation</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Issued</th>
                <th className="px-4 py-2">Integrity</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {certs.map((c) => (
                <tr key={c.id} className="border-t border-slate-800/60 bg-slate-900/30">
                  <td className="px-4 py-2 text-slate-300">{c.id}</td>
                  <td className="px-4 py-2 text-slate-400">{c.operation_id}</td>
                  <td className="px-4 py-2">
                    <StatusBadge status={c.final_status} />
                  </td>
                  <td className="px-4 py-2 text-slate-500">{new Date(c.issued_at).toLocaleString()}</td>
                  <td className="px-4 py-2">
                    {verifyResults[c.id] ? (
                      <span className={verifyResults[c.id].valid ? "text-emerald-400" : "text-rose-400"}>
                        {verifyResults[c.id].valid ? "Valid" : "Invalid"}
                      </span>
                    ) : (
                      <button onClick={() => verify(c.id)} className="text-xs text-trust-600 hover:underline">
                        Check
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <a
                      href={api.downloadCertificateUrl(c.id)}
                      className="rounded bg-trust-700 px-2 py-1 text-xs font-medium text-white hover:bg-trust-600"
                    >
                      Download
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
