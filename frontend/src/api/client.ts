import type {
  AuditChainStatus,
  AuditEvent,
  Certificate,
  CertificateVerifyResult,
  DashboardSummary,
  DevicesResponse,
  Operation,
  SanitizationMethod,
} from "../types/api";

const BASE = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function operatorToken(): string {
  return localStorage.getItem("zerotrace_operator_token") || "";
}

export function setOperatorToken(token: string) {
  localStorage.setItem("zerotrace_operator_token", token);
}

async function request<T>(path: string, options: RequestInit = {}, authed = false): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (authed) {
    headers["X-Operator-Token"] = operatorToken();
  }
  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      /* ignore parse failure */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; app_name: string; app_version: string }>("/health"),
  devices: () => request<DevicesResponse>("/devices"),
  methods: () => request<SanitizationMethod[]>("/methods"),

  listOperations: () => request<Operation[]>("/operations"),
  getOperation: (id: string) => request<Operation>(`/operations/${id}`),
  createOperation: (payload: {
    target_type: "demo" | "image" | "physical";
    target_identifier?: string;
    method: string;
    capacity_bytes?: number;
    confirm_phrase?: string;
    acknowledge_irrecoverable?: boolean;
  }) => request<Operation>("/operations", { method: "POST", body: JSON.stringify(payload) }, true),
  reverifyOperation: (id: string) => request<Operation>(`/operations/${id}/verify`, { method: "POST" }, true),

  listCertificates: () => request<Certificate[]>("/certificates"),
  getCertificate: (id: string) => request<Certificate>(`/certificates/${id}`),
  createCertificate: (operationId: string) =>
    request<Certificate>(`/certificates/for-operation/${operationId}`, { method: "POST" }, true),
  verifyCertificate: (id: string) =>
    request<CertificateVerifyResult>(`/certificates/${id}/verify`, { method: "POST" }),
  downloadCertificateUrl: (id: string) => `${BASE}/certificates/${id}/download`,

  listAuditEvents: () => request<AuditEvent[]>("/audit"),
  auditChainStatus: () => request<AuditChainStatus>("/audit/verify-chain"),

  dashboardSummary: () => request<DashboardSummary>("/dashboard/summary"),
};
