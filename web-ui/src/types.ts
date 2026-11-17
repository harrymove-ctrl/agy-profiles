export type AppView = "profiles" | "handoff" | "obligations" | "doctor";

export type ProfileFilter = "all" | "running" | "stopped" | "stale-lock";

export type TargetKind = "hub" | "ide";

export type LinkPolicy = "none" | "minimal" | "dev";

export type AuthMode = "isolated-file" | "system-keychain";

export type AutomationsMode = "paused" | "active" | "strip";

export type RuntimeStateType = "running" | "stopped" | "stale-lock";

export interface TargetRuntime {
  target: TargetKind;
  state: RuntimeStateType;
  root_pids?: number[];
  pids: number[];
  schedule_count?: number;
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
  account?: ProfileAccountInfo;
  sync_state?: ProfileSyncState;
  disk_bytes: number;
}

export interface ProfileAccountInfo {
  email: string | null;
  source: string;
  auth_method: string | null;
  oauth_present: boolean;
}

export interface ProfileSyncState {
  projects_count: number;
  sessions_count?: number;
  agents_count: number;
  plugins_count: number;
  skills_count: number;
  automations_count?: number;
  automations_enabled?: number;
  hooks_present?: boolean;
  mcp_present: boolean;
  gemini_md_present: boolean;
  handoff_present: boolean;
}

export interface HostAccountInfo extends ProfileAccountInfo {
  app_storage_email?: string | null;
  google_accounts_active?: string | null;
  projects_count: number;
  sessions_count?: number;
  plugins_count: number;
  agents_count: number;
  skills_count: number;
  automations_count?: number;
  automations_enabled?: number;
  hooks_present?: boolean;
  mcp_present: boolean;
  handoff_present?: boolean;
}

export interface HostRuntimeInfo {
  hub: TargetRuntime;
  ide: TargetRuntime;
}

export type QuotaFlowMode =
  | "no_profiles"
  | "host_primary"
  | "backup_active"
  | "dual_active";

export interface QuotaFlowInfo {
  mode: QuotaFlowMode;
  active_owner: string;
  active_profiles: string[];
  standby_profiles: string[];
  host_running: boolean;
  host_schedule_count: number;
  dual_automations_warning: boolean;
  summary: string;
}

export interface IsolationPermissions {
  profile_dir: string | null;
  data_dir: string | null;
  sandbox_home: string | null;
  oauth_token_file: string | null;
  mcp_config_file: string | null;
  handoff_file?: string | null;
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
  sync_state?: ProfileSyncState;
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
  host_account?: HostAccountInfo;
  host_runtime?: HostRuntimeInfo;
  flow?: QuotaFlowInfo;
  targets: {
    hub: TargetInfo;
    ide: TargetInfo;
  };
  profiles: ProfileSummary[];
  server: {
    version: string;
    origin: string;
    sidecar_mode?: boolean;
  };
}

export type HandoffConversation = {
  conversation_id: string;
  title: string;
  project: string;
  workspace: string;
  status: string;
  updated_at: string;
  last_user_request: string;
  last_agent_summary: string;
};

export interface HandoffResponse {
  available: boolean;
  source?: string;
  source_account?: string | null;
  db_path: string;
  generated_at: string;
  host_account: string | null;
  count: number;
  conversations: HandoffConversation[];
  resume_prompt: string;
  reason?: string;
  host_account_details?: HostAccountInfo;
  evidence: EvidenceRecord;
}

export interface SessionSyncSummary {
  synced_sessions: number;
  skipped_up_to_date: number;
  total_dst_sessions: number;
  worktrees_linked: number;
  proto_rebuilt: boolean;
}

export interface SyncProfilePayload {
  include_sidecars?: boolean;
  automations_mode?: AutomationsMode;
  from_source?: string;
  include_handoff?: boolean;
  include_sessions?: boolean;
  session_limit?: number;
  restart?: boolean;
  limit?: number;
}

export interface SyncResultSummary {
  copied: string[];
  redacted_secrets: number;
  stripped_sidecars: number;
  pruned_entries?: number;
  automations_mode?: AutomationsMode;
  automations_synced?: number;
  automations_enabled?: number;
  projects_synced: number;
  sessions_synced?: number;
  sessions?: SessionSyncSummary;
  agents_synced: number;
  plugins_synced: number;
  skills_synced: number;
  tree_files_copied: number;
  handoff: {
    written: boolean;
    path: string | null;
    count: number;
    source?: string;
    reason?: string;
  };
  sync_state: ProfileSyncState;
  synced_at: string;
}

export interface SyncProfileResponse extends ProfileSummary {
  sync: SyncResultSummary;
  restarted: boolean;
  evidence: EvidenceRecord;
}

export interface GitStatusInfo {
  workspace: string | null;
  is_git: boolean;
  dirty: boolean;
  modified_count: number;
}

export interface SwitchProfileResponse extends ProfileSummary {
  sync: SyncResultSummary;
  switch: {
    target: TargetKind;
    automations_mode: AutomationsMode;
    from_source: string;
    git_status: GitStatusInfo;
    prompt_copied: boolean;
    resume_prompt: string;
    launched?: Record<string, unknown> | null;
  };
  evidence: EvidenceRecord;
}

export interface ReturnHostSwitchResponse {
  target_profile: "host";
  from_source: string;
  handoff: {
    written: boolean;
    path: string | null;
    count: number;
    source?: string;
    reason?: string;
  };
  sessions?: SessionSyncSummary;
  sync: SyncResultSummary;
  backup_profile?: ProfileSummary | null;
  host_account: HostAccountInfo;
  host_runtime: HostRuntimeInfo;
  flow: QuotaFlowInfo;
  switch: {
    target: TargetKind;
    automations_mode: AutomationsMode;
    from_source: string;
    git_status: GitStatusInfo;
    prompt_copied: boolean;
    resume_prompt: string;
    relaunched_backup?: Array<Record<string, unknown>>;
  };
  evidence: EvidenceRecord;
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
  fresh_auth?: boolean;
}

export interface RenameProfilePayload {
  target: string;
  label?: string;
  restart?: boolean;
}
