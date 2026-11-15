import type { ThemeSlug } from "./astryx-themes";
import type { RuntimeStateType, TargetRuntime } from "./types";

export interface AccentPreset {
  key: string;
  label: string;
  hex: string;
}

export const ACCENT_PRESETS: ReadonlyArray<AccentPreset> = [
  { key: "ochre", label: "Warm Ochre", hex: "#B45309" },
  { key: "moss", label: "Sage Moss", hex: "#3F6212" },
  { key: "verdigris", label: "Deep Verdigris", hex: "#0F766E" },
  { key: "carmine", label: "Oxide Carmine", hex: "#9F1239" },
  { key: "slate", label: "Mineral Slate", hex: "#57534E" },
  { key: "sienna", label: "Burnt Sienna", hex: "#7C2D12" },
];

export interface ThemeOption {
  value: ThemeSlug;
  label: string;
  description: string;
}

export const THEME_OPTIONS: ThemeOption[] = [
  { value: "stone", label: "Stone", description: "Warm mineral paper and bronze focus" },
  { value: "chocolate", label: "Chocolate", description: "Rich cocoa surface and copper amber" },
  { value: "gothic", label: "Gothic", description: "Candlelit obsidian dark workspace" },
  { value: "matcha", label: "Matcha", description: "Botanical sage and warm cream" },
  { value: "neutral", label: "Neutral", description: "Crisp neutral studio canvas" },
];

export function resolveAccentKey(hex: string): string {
  const normalized = (hex || "").trim().toUpperCase();
  const matched = ACCENT_PRESETS.find((preset) => preset.hex.toUpperCase() === normalized);
  return matched ? matched.key : "ochre";
}

export function stripBootstrapTokenFromUrl(): void {
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

export function profileInitials(label: string, slug: string): string {
  const source = (label || slug || "AP").trim();
  const words = source.split(/[\s._-]+/).filter(Boolean);
  if (words.length >= 2) {
    return `${words[0][0]}${words[1][0]}`.toUpperCase();
  }
  return source.slice(0, 2).toUpperCase();
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
