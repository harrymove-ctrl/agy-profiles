import type { ThemeSlug } from "./astryx-themes";
import type { AuthMode, LinkPolicy, RuntimeStateType, TargetRuntime } from "./types";

export interface AccentPreset {
  key: string;
  label: string;
  hex: string;
}

export const ACCENT_PRESETS: ReadonlyArray<AccentPreset> = [
  { key: "ochre", label: "Ochre", hex: "#B45309" },
  { key: "moss", label: "Moss", hex: "#3F6212" },
  { key: "verdigris", label: "Verdigris", hex: "#0F766E" },
  { key: "carmine", label: "Carmine", hex: "#9F1239" },
  { key: "slate", label: "Slate", hex: "#57534E" },
  { key: "sienna", label: "Sienna", hex: "#7C2D12" },
];

export interface ThemeOption {
  value: ThemeSlug;
  label: string;
  description: string;
}

export const THEME_OPTIONS: ThemeOption[] = [
  {
    value: "gothic-studio",
    label: "Gothic Studio",
    description: "Refined dark slate console with Fustat typography",
  },
  {
    value: "gothic",
    label: "Gothic",
    description: "Editorial blue-gray dark surfaces from Astryx",
  },
  {
    value: "neutral",
    label: "Neutral",
    description: "Clean neutral workspace with light and dark modes",
  },
];

const INITIAL_URL_PARAMS =
  typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
const INITIAL_BOOT_TOKEN = INITIAL_URL_PARAMS?.get("token") ?? "";
const IS_EMBEDDED_SIDECAR =
  typeof window !== "undefined" &&
  (Boolean(INITIAL_URL_PARAMS?.has("conversationId")) || window.parent !== window);

export function isEmbeddedSidecar(): boolean {
  return IS_EMBEDDED_SIDECAR;
}

export async function startSidecarConversation(
  message: string,
  title?: string
): Promise<boolean> {
  const bridge = (
    window as unknown as {
      sidecar?: {
        agent?: {
          startConversation?: (msg: string, title?: string) => Promise<unknown>;
        };
      };
    }
  ).sidecar;
  if (!bridge?.agent?.startConversation) {
    return false;
  }
  await bridge.agent.startConversation(message, title);
  return true;
}

export function stripBootstrapTokenFromUrl(): void {
  if (IS_EMBEDDED_SIDECAR) {
    return;
  }
  const params = new URLSearchParams(window.location.search);
  if (!params.has("token")) {
    return;
  }
  params.delete("token");
  const nextQuery = params.toString();
  const cleanUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ""}${window.location.hash}`;
  window.history.replaceState({}, "", cleanUrl);
}

export function getCsrfToken(): string {
  const meta = document.querySelector('meta[name="agy-csrf"]');
  return meta?.getAttribute("content") ?? "";
}

export class ApiClientError extends Error {
  code: string;
  remediation: string;
  status: number;

  constructor(message: string, code = "request_failed", remediation = "", status = 500) {
    super(message);
    this.name = "ApiClientError";
    this.code = code;
    this.remediation = remediation;
    this.status = status;
  }
}

export async function apiFetch<T>(
  path: string,
  options?: { method?: string; body?: object }
): Promise<T> {
  const method = options?.method ?? "GET";
  const headers: Record<string, string> = {
    "X-AGY-CSRF": getCsrfToken(),
  };
  if (INITIAL_BOOT_TOKEN) {
    headers["X-Sidecar-Token"] = INITIAL_BOOT_TOKEN;
  }
  let payload: string | undefined;
  if (options?.body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(options.body);
  }

  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    body: payload,
  });

  const text = await res.text();
  let data: unknown = {};
  if (text.trim().length > 0) {
    try {
      data = JSON.parse(text);
    } catch {
      if (!res.ok) {
        throw new ApiClientError(
          `Request failed with HTTP ${res.status}`,
          "invalid_response",
          "",
          res.status
        );
      }
      throw new ApiClientError("Server returned non-JSON response", "invalid_response", "", res.status);
    }
  }

  if (!res.ok) {
    const errObj =
      typeof data === "object" && data !== null && "error" in data
        ? (data as { error?: { message?: string; code?: string; remediation?: string } }).error
        : undefined;
    throw new ApiClientError(
      errObj?.message || `Request failed (${res.status})`,
      errObj?.code || "request_failed",
      errObj?.remediation || "",
      res.status
    );
  }

  return data as T;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  if (idx === 0) {
    return `${Math.round(value)} B`;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[idx]}`;
}

export function computeCombinedState(rt: {
  hub: TargetRuntime;
  ide: TargetRuntime;
}): RuntimeStateType {
  if (rt.hub.state === "running" || rt.ide.state === "running") {
    return "running";
  }
  if (rt.hub.state === "stale-lock" || rt.ide.state === "stale-lock") {
    return "stale-lock";
  }
  return "stopped";
}

export function pluralize(count: number, singular: string, plural = `${singular}s`): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

export function formatTargetPidSummary(rt: TargetRuntime): string {
  if (rt.pids.length === 0) {
    return pluralize(rt.lock_files.length, "lock");
  }
  const roots =
    rt.root_pids && rt.root_pids.length > 0
      ? rt.root_pids
      : rt.pids.slice(0, 2);
  const rootLabel = `PID ${roots.join(", ")}`;
  if (rt.pids.length > roots.length) {
    return `${rootLabel} · ${pluralize(rt.pids.length, "process", "processes")}`;
  }
  return rootLabel;
}

export function formatRuntimeState(state: RuntimeStateType): string {
  if (state === "running") {
    return "Running";
  }
  if (state === "stale-lock") {
    return "Stale lock";
  }
  return "Stopped";
}

export function formatAuthMode(mode: AuthMode): string {
  return mode === "isolated-file" ? "Isolated file" : "System keychain";
}

export function formatLinkPolicy(policy: LinkPolicy): string {
  if (policy === "none") {
    return "No host links";
  }
  if (policy === "dev") {
    return "Dev cache links";
  }
  return "Minimal links";
}
