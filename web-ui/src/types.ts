export type AppView = "profiles" | "obligations" | "doctor";

export type ProfileFilter = "all" | "running" | "stopped" | "stale-lock";

export type TargetKind = "hub" | "ide";

export type LinkPolicy = "none" | "minimal" | "dev";

export type AuthMode = "isolated-file" | "system-keychain";

export type RuntimeStateType = "running" | "stopped" | "stale-lock";

export interface TargetRuntime {
  target: TargetKind;
  state: RuntimeStateType;
  pids: number[];
  lock_files: string[];
}

export interface ProfileManifest {
  schema_version: number;
  name: string;
  label: string;
  accent: string;
  default_target: TargetKind;
  link_policy: LinkPolicy;
  auth_mode: AuthMode;
  keep_background_alive: boolean;
  created_at: string;
  updated_at: string;
  last_launched_at: string | null;
  last_host_versions: Record<string, string>;
}

export interface ProfilePaths {
  profile_dir: string;
  data_dir: string;
  ide_data_dir: string;
  sandbox_home: string;
}

export interface ProfileSummary {
  manifest: ProfileManifest;
  paths: ProfilePaths;
  runtime: {
    hub: TargetRuntime;
    ide: TargetRuntime;
  };
  launchers: {
    hub: boolean;
    ide: boolean;
  };
  disk_bytes: number;
}

export interface IsolationPermissions {
  profile_dir: string | null;
  data_dir: string | null;
  sandbox_home: string | null;
  oauth_token_file: string | null;
  mcp_config_file: string | null;
  zshenv_file: string | null;
}

export interface IsolationAudit {
  permissions: IsolationPermissions;
  auth_mode: AuthMode;
  link_policy: LinkPolicy;
  zshenv_home_locked: boolean;
  oauth_token_present: boolean;
  forbidden_symlinks_present: string[];
  active_symlinks: Array<{ relpath: string; target: string }>;
}

export interface EvidenceRecord {
  evidence_id: string;
  operation: string;
  authority: string;
  confidence: string;
  summary: string;
  facts: Record<string, unknown>;
  limitations: string[];
  observed_at: string;
}

export interface ProfileDetail extends ProfileSummary {
  isolation: IsolationAudit;
  evidence: EvidenceRecord;
}

export interface TargetInfo {
  kind: TargetKind;
  display_name: string;
  app_path: string | null;
  binary_path: string | null;
  bundle_id: string;
  version: string;
  installed: boolean;
}

export interface OverviewResponse {
  root: string;
  default_root: string;
  targets: {
    hub: TargetInfo;
    ide: TargetInfo;
  };
  profiles: ProfileSummary[];
  server: {
    version: string;
    origin: string;
  };
}

export interface ObligationItem extends Record<string, unknown> {
  obligation_id: string;
  title: string;
  status: "closed" | "failed" | string;
  owner_module: string;
  module_sha256: string;
  cases_checked: string[];
  detail: string;
  evidence_id: string;
}

export interface ObligationsResponse {
  ledger_id: string;
  verified_at: string;
  summary: {
    total: number;
    closed: number;
    failed: number;
  };
  items: ObligationItem[];
  evidence: EvidenceRecord[];
}

export interface DoctorCheck extends Record<string, unknown> {
  id: string;
  status: "pass" | "warn" | "fail" | string;
  detail: string;
}

export interface DoctorResponse {
  checks: DoctorCheck[];
  targets: {
    hub: TargetInfo;
    ide: TargetInfo;
  };
  evidence: EvidenceRecord;
}

export interface CreateProfilePayload {
  name: string;
  label?: string;
  accent?: string;
  default_target?: TargetKind;
  link_policy?: LinkPolicy;
  auth_mode?: AuthMode;
  keep_background_alive?: boolean;
  inherit_config?: boolean;
}

export interface UpdateProfilePayload {
  label?: string;
  accent?: string;
  default_target?: TargetKind;
  link_policy?: LinkPolicy;
  auth_mode?: AuthMode;
  keep_background_alive?: boolean;
}

export interface CloneProfilePayload {
  target: string;
  label?: string;
}
