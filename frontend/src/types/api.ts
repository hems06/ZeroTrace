export interface PhysicalDevice {
  device_id: string;
  name: string;
  capacity_bytes: number | null;
  interface: string | null;
  media_type: string | null;
  is_system_disk: boolean;
  is_mounted: boolean;
  mount_points: string[];
  partitions: Record<string, unknown>[];
}

export interface ImageTarget {
  identifier: string;
  target_type: "image";
  size_bytes: number;
  marker_count: number;
  media_type_label: string;
  description: string;
}

export interface DevicesResponse {
  physical_devices: PhysicalDevice[];
  image_targets: ImageTarget[];
  discovery_warnings: string[];
}

export interface SanitizationMethod {
  key: string;
  label: string;
  policy_level: "clear" | "purge" | "destroy";
  policy_reference: string;
  limitations: string;
}

export type TargetType = "demo" | "image" | "physical";

export interface Operation {
  id: string;
  target_type: TargetType;
  target_identifier: string;
  target_label: string;
  capacity_bytes: number | null;
  media_type: string | null;
  method: string;
  policy_level: string;
  policy_reference: string;
  status: string;
  verification_status: string;
  simulation_only: boolean;
  operator_id: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  evidence: Record<string, unknown>;
  errors: string[];
  warnings: string[];
  limitations: string[];
}

export interface Certificate {
  id: string;
  operation_id: string;
  final_status: string;
  content_hash: string;
  signature_algorithm: string;
  public_key_fingerprint: string | null;
  issued_at: string;
}

export interface CertificateVerifyResult {
  valid: boolean;
  hash_matches?: boolean;
  signature_valid?: boolean;
  fingerprint_matches?: boolean;
  recomputed_hash?: string;
  stored_hash?: string;
  reason?: string;
}

export interface AuditEvent {
  seq: number;
  operation_id: string | null;
  event_type: string;
  timestamp: string;
  evidence: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

export interface AuditChainStatus {
  intact: boolean;
  total_events: number;
  first_invalid_seq: number | null;
  limitation: string;
}

export interface DashboardSummary {
  total_operations: number;
  verified_count: number;
  failed_count: number;
  inconclusive_count: number;
  image_based_operations: number;
  demo_operations: number;
  physical_operations: number;
  total_certificates: number;
  total_audit_events: number;
  recent_operations: {
    id: string;
    target_type: string;
    target_label: string;
    status: string;
    verification_status: string;
    simulation_only: boolean;
    created_at: string;
  }[];
}
