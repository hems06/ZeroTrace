import { useEffect, useState } from "react";
import { api, ApiError, setOperatorToken } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type {
  Certificate,
  CertificateVerifyResult,
  DevicesResponse,
  Operation,
  PhysicalDevice,
  SanitizationMethod,
  TargetType,
} from "../types/api";

const REQUIRED_PHRASE = "I UNDERSTAND DATA WILL BECOME IRRECOVERABLE";

function formatBytes(n: number | null): string {
  if (n === null) return "unknown";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return `${v.toFixed(1)} ${units[i]}`;
}

export default function Sanitize() {
  const [devices, setDevices] = useState<DevicesResponse | null>(null);
  const [methods, setMethods] = useState<SanitizationMethod[]>([]);
  const [targetType, setTargetType] = useState<TargetType>("image");
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<PhysicalDevice | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<string>("");
  const [acknowledge, setAcknowledge] = useState(false);
  const [confirmPhrase, setConfirmPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Operation | null>(null);
  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const [certVerify, setCertVerify] = useState<CertificateVerifyResult | null>(null);

  const loadDevices = () => {
    api.devices().then(setDevices).catch((e) => setError(e.message));
  };

  useEffect(() => {
    loadDevices();
    api.methods().then(setMethods).catch((e) => setError(e.message));
    if (!localStorage.getItem("zerotrace_operator_token")) {
      setOperatorToken("demo-token");
    }
  }, []);

  const resetOutcome = () => {
    setResult(null);
    setCertificate(null);
    setCertVerify(null);
    setError(null);
  };

  const canExecute =
    selectedMethod !== "" &&
    (targetType === "demo" ||
      (targetType === "image" && selectedImage) ||
      (targetType === "physical" && selectedDevice && acknowledge && confirmPhrase === REQUIRED_PHRASE));

  const execute = async () => {
    setBusy(true);
    resetOutcome();
    try {
      const op = await api.createOperation({
        target_type: targetType,
        target_identifier:
          targetType === "image" ? selectedImage ?? "" : targetType === "physical" ? selectedDevice?.device_id ?? "" : "",
        method: selectedMethod,
        acknowledge_irrecoverable: targetType === "physical" ? acknowledge : undefined,
        confirm_phrase: targetType === "physical" ? confirmPhrase : undefined,
      });
      setResult(op);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const generateCertificate = async () => {
    if (!result) return;
    setBusy(true);
    try {
      const cert = await api.createCertificate(result.id);
      setCertificate(cert);
      const verify = await api.verifyCertificate(cert.id);
      setCertVerify(verify);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">1. Choose a target</h2>
          <button onClick={loadDevices} className="text-xs text-trust-600 hover:underline">
            Re-run discovery
          </button>
        </div>
        <div className="mb-4 flex gap-2">
          {(["demo", "physical", "image"] as TargetType[]).map((t) => (
            <button
              key={t}
              onClick={() => {
                setTargetType(t);
                setSelectedImage(null);
                setSelectedDevice(null);
                resetOutcome();
              }}
              className={`rounded-md px-3 py-1.5 text-xs font-medium ${
                targetType === t ? "bg-trust-700 text-white" : "bg-slate-800 text-slate-400 hover:bg-slate-700"
              }`}
            >
              {t === "demo" ? "Demonstration" : t === "image" ? "Image-based test" : "Physical device"}
            </button>
          ))}
        </div>

        {targetType === "demo" && (
          <div className="rounded-lg border border-indigo-800 bg-indigo-950/30 p-3 text-sm text-indigo-200">
            Operates only on a freshly generated synthetic dataset inside an isolated workspace. No real
            device, image, or file is touched. Always available, no USB required.
          </div>
        )}

        {targetType === "image" && (
          <div className="space-y-2">
            {devices?.discovery_warnings.map((w) => (
              <div key={w} className="rounded bg-amber-950/40 px-3 py-1.5 text-xs text-amber-300">{w}</div>
            ))}
            {devices?.image_targets.length === 0 && (
              <div className="rounded border border-dashed border-slate-700 p-4 text-center text-sm text-slate-500">
                No image targets found. Generate one with{" "}
                <code className="text-slate-300">python demo_data/generate_sample_image.py</code> under
                backend/instance/images, then re-run discovery.
              </div>
            )}
            <div className="grid gap-2 md:grid-cols-2">
              {devices?.image_targets.map((img) => (
                <button
                  key={img.identifier}
                  onClick={() => setSelectedImage(img.identifier)}
                  className={`rounded-lg border p-3 text-left text-sm transition ${
                    selectedImage === img.identifier
                      ? "border-trust-600 bg-trust-900/30"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  }`}
                >
                  <div className="font-medium text-slate-200">{img.identifier}</div>
                  <div className="mt-1 text-xs text-slate-500">
                    {formatBytes(img.size_bytes)} · {img.media_type_label} · {img.marker_count} marker record(s)
                  </div>
                  <div className="mt-1 text-xs text-slate-600">{img.description}</div>
                </button>
              ))}
            </div>
          </div>
        )}

        {targetType === "physical" && (
          <div className="space-y-2">
            {devices?.physical_devices.length === 0 && (
              <div className="rounded border border-dashed border-slate-700 p-4 text-center text-sm text-slate-500">
                No physical storage devices detected by the OS.
              </div>
            )}
            <div className="grid gap-2 md:grid-cols-2">
              {devices?.physical_devices.map((d) => (
                <button
                  key={d.device_id}
                  disabled={d.is_system_disk}
                  onClick={() => setSelectedDevice(d)}
                  className={`rounded-lg border p-3 text-left text-sm transition disabled:cursor-not-allowed disabled:opacity-50 ${
                    selectedDevice?.device_id === d.device_id
                      ? "border-trust-600 bg-trust-900/30"
                      : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  }`}
                >
                  <div className="font-medium text-slate-200">{d.name}</div>
                  <div className="mt-1 text-xs text-slate-500">
                    {formatBytes(d.capacity_bytes)} · {d.interface ?? "unknown interface"} ·{" "}
                    {d.media_type ?? "unknown media"}
                  </div>
                  {d.is_system_disk && (
                    <div className="mt-1 text-xs font-semibold text-rose-400">
                      BLOCKED: hosts the operating system — cannot be selected
                    </div>
                  )}
                  {!d.is_system_disk && d.is_mounted && (
                    <div className="mt-1 text-xs text-amber-400">Mounted: {d.mount_points.join(", ") || "yes"}</div>
                  )}
                </button>
              ))}
            </div>
            {selectedDevice && selectedDevice.is_mounted && (
              <div className="rounded-lg border border-amber-700 bg-amber-950/30 p-3 text-xs text-amber-200">
                <div className="flex items-center gap-1.5 font-semibold text-amber-300">
                  <svg xmlns="http://www.w3.org/2000/svg" className="h-3.5 w-3.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-5a1 1 0 00-1 1v3a1 1 0 102 0v-3a1 1 0 00-1-1z" clipRule="evenodd"/>
                  </svg>
                  Device mounted at <span className="font-mono">{selectedDevice.mount_points.join(", ")}</span> — will be auto-unmounted before sanitization
                </div>
              </div>
            )}
            {selectedDevice && (
              <div className="rounded-lg border border-rose-800 bg-rose-950/30 p-3 text-sm text-rose-200">
                <div className="font-semibold">Destructive operation — data WILL become irrecoverable</div>
                <label className="mt-2 flex items-center gap-2 text-xs">
                  <input type="checkbox" checked={acknowledge} onChange={(e) => setAcknowledge(e.target.checked)} />
                  I have authorization to sanitize {selectedDevice.name} ({selectedDevice.device_id}) and
                  understand data will become irrecoverable.
                </label>
                <input
                  value={confirmPhrase}
                  onChange={(e) => setConfirmPhrase(e.target.value)}
                  placeholder={`Type exactly: ${REQUIRED_PHRASE}`}
                  className="mt-2 w-full rounded border border-rose-700 bg-slate-950 px-2 py-1 text-xs text-slate-200 outline-none"
                />
              </div>
            )}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">2. Choose sanitization policy</h2>
        <div className="grid gap-2 md:grid-cols-3">
          {methods.map((m) => (
            <button
              key={m.key}
              onClick={() => setSelectedMethod(m.key)}
              className={`rounded-lg border p-3 text-left text-xs transition ${
                selectedMethod === m.key
                  ? "border-trust-600 bg-trust-900/30"
                  : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
              }`}
            >
              <div className="font-medium text-slate-200">{m.label}</div>
              <div className="mt-1 text-slate-500">{m.policy_reference}</div>
              <div className="mt-1 text-slate-600">{m.limitations}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">3. Review &amp; execute</h2>
        <div className="mb-3 text-sm text-slate-400">
          Target: <span className="text-slate-200">{targetType}</span>
          {targetType === "image" && selectedImage && <span className="text-slate-200"> — {selectedImage}</span>}
          {targetType === "physical" && selectedDevice && (
            <span className="text-slate-200"> — {selectedDevice.name}</span>
          )}
          {" · "}Method: <span className="text-slate-200">{selectedMethod || "none selected"}</span>
        </div>
        <button
          disabled={!canExecute || busy}
          onClick={execute}
          className="rounded-md bg-trust-700 px-4 py-2 text-sm font-semibold text-white transition disabled:cursor-not-allowed disabled:opacity-40 hover:bg-trust-600"
        >
          {busy ? "Working…" : "Execute operation"}
        </button>
        {error && <div className="mt-3 rounded bg-rose-950/40 px-3 py-2 text-sm text-rose-300">{error}</div>}
      </div>

      {result && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="mb-3 flex items-center gap-2">
            <h2 className="text-sm font-semibold text-slate-200">Outcome</h2>
            <StatusBadge status={result.status} />
            <StatusBadge status={result.verification_status} />
            {result.simulation_only && <StatusBadge status="Simulation Only" />}
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <div className="mb-1 text-xs font-semibold uppercase text-slate-500">Evidence</div>
              <pre className="max-h-48 overflow-auto rounded bg-slate-950 p-2 text-xs text-slate-400">
                {JSON.stringify(result.evidence, null, 2)}
              </pre>
            </div>
            <div className="space-y-2">
              {result.errors.length > 0 && (
                <div>
                  <div className="mb-1 text-xs font-semibold uppercase text-rose-500">Errors</div>
                  <ul className="list-inside list-disc text-xs text-rose-300">
                    {result.errors.map((e, i) => (
                      <li key={i}>{e}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.warnings.length > 0 && (
                <div>
                  <div className="mb-1 text-xs font-semibold uppercase text-amber-500">Warnings</div>
                  <ul className="list-inside list-disc text-xs text-amber-300">
                    {result.warnings.map((w, i) => (
                      <li key={i}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
              <div>
                <div className="mb-1 text-xs font-semibold uppercase text-slate-500">Scope &amp; limitations</div>
                <ul className="list-inside list-disc text-xs text-slate-400">
                  {result.limitations.map((l, i) => (
                    <li key={i}>{l}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>

          <div className="mt-4 border-t border-slate-800 pt-4">
            {!certificate ? (
              <button
                onClick={generateCertificate}
                disabled={busy}
                className="rounded-md bg-emerald-700 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-600 disabled:opacity-40"
              >
                Generate certificate
              </button>
            ) : (
              <div className="flex items-center gap-3 text-sm">
                <StatusBadge status={certificate.final_status} />
                <span className="text-slate-400">{certificate.id}</span>
                {certVerify && (
                  <span className={certVerify.valid ? "text-emerald-400" : "text-rose-400"}>
                    {certVerify.valid ? "Integrity verified" : "Verification FAILED"}
                  </span>
                )}
                <a
                  href={api.downloadCertificateUrl(certificate.id)}
                  className="rounded bg-trust-700 px-3 py-1.5 font-medium text-white hover:bg-trust-600"
                >
                  Download PDF
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
