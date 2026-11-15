import { useCallback, useEffect, useRef, useState } from "react";
import { AppShell } from "@astryxdesign/core/AppShell";
import { Theme } from "@astryxdesign/core/theme";
import { ToastViewport, useToast } from "@astryxdesign/core/Toast";
import { defaultThemeSlug, themes, type ThemeSlug } from "./astryx-themes";
import { ApiClientError, apiFetch, stripBootstrapTokenFromUrl } from "./api";
import { DoctorStage } from "./components/DoctorStage";
import { ObligationsStage } from "./components/ObligationsStage";
import {
  CloneProfileDrawer,
  CreateProfileDrawer,
} from "./components/ProfileDialogs";
import {
  ProfilesDetailPane,
  ProfilesSideRail,
} from "./components/ProfilesWorkspace";
import { TopBar } from "./components/TopBar";
import type {
  AppView,
  CloneProfilePayload,
  CreateProfilePayload,
  DoctorResponse,
  ObligationsResponse,
  OverviewResponse,
  ProfileDetail,
  ProfileFilter,
  TargetKind,
  UpdateProfilePayload,
} from "./types";

const THEME_STORAGE_KEY = "agyp-astryx-theme";
const MODE_STORAGE_KEY = "agyp-color-scheme";

function readStoredTheme(): ThemeSlug {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw && raw in themes) {
      return raw as ThemeSlug;
    }
  } catch {
    // Ignore storage read failures in locked browsing contexts.
  }
  return defaultThemeSlug;
}

function readStoredMode(): "light" | "dark" {
  try {
    const raw = localStorage.getItem(MODE_STORAGE_KEY);
    if (raw === "dark" || raw === "light") {
      return raw;
    }
  } catch {
    // Ignore storage read failures.
  }
  return "light";
}

interface ConsoleShellProps {
  themeSlug: ThemeSlug;
  resolvedMode: "light" | "dark";
  onThemeChange: (slug: ThemeSlug) => void;
  onToggleColorMode: () => void;
}

function ConsoleShell({
  themeSlug,
  resolvedMode,
  onThemeChange,
  onToggleColorMode,
}: ConsoleShellProps) {
  const toast = useToast();
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const [view, setView] = useState<AppView>("profiles");
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [selectedName, setSelectedName] = useState<string | null>(null);
  const [detail, setDetail] = useState<ProfileDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [searchQuery, setSearchQuery] = useState("");
  const [runtimeFilter, setRuntimeFilter] = useState<ProfileFilter>("all");
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [confirmDeleteOpen, setConfirmDeleteOpen] = useState(false);

  const [createOpen, setCreateOpen] = useState(false);
  const [cloneOpen, setCloneOpen] = useState(false);

  const [obligations, setObligations] = useState<ObligationsResponse | null>(null);
  const [obligationsLoading, setObligationsLoading] = useState(false);
  const [doctor, setDoctor] = useState<DoctorResponse | null>(null);
  const [doctorLoading, setDoctorLoading] = useState(false);

  const reportError = useCallback(
    (err: unknown, fallback: string) => {
      if (err instanceof ApiClientError) {
        const suffix = err.remediation ? ` — ${err.remediation}` : "";
        toast({ body: `${err.message}${suffix}`, type: "error" });
        return;
      }
      toast({
        body: err instanceof Error ? err.message : fallback,
        type: "error",
      });
    },
    [toast]
  );

  const loadDetail = useCallback(
    async (name: string) => {
      setDetailLoading(true);
      try {
        const data = await apiFetch<ProfileDetail>(
          `/api/profiles/${encodeURIComponent(name)}`
        );
        setDetail(data);
      } catch (err) {
        reportError(err, `Failed to load profile "${name}".`);
      } finally {
        setDetailLoading(false);
      }
    },
    [reportError]
  );

  const refreshState = useCallback(
    async (preferredName?: string | null) => {
      try {
        const data = await apiFetch<OverviewResponse>("/api/state");
        setOverview(data);

        const names = data.profiles.map((p) => p.manifest.name);
        let nextSelected = preferredName ?? selectedName;
        if (!nextSelected || !names.includes(nextSelected)) {
          nextSelected = names[0] ?? null;
        }
        setSelectedName(nextSelected);
        if (nextSelected) {
          await loadDetail(nextSelected);
        } else {
          setDetail(null);
        }
      } catch (err) {
        reportError(err, "Failed to load console overview.");
      }
    },
    [loadDetail, reportError, selectedName]
  );

  const loadObligations = useCallback(async () => {
    setObligationsLoading(true);
    try {
      const data = await apiFetch<ObligationsResponse>("/api/obligations");
      setObligations(data);
    } catch (err) {
      reportError(err, "Failed to verify security obligations.");
    } finally {
      setObligationsLoading(false);
    }
  }, [reportError]);

  const loadDoctor = useCallback(async () => {
    setDoctorLoading(true);
    try {
      const data = await apiFetch<DoctorResponse>("/api/doctor");
      setDoctor(data);
    } catch (err) {
      reportError(err, "Failed to run host diagnostics.");
    } finally {
      setDoctorLoading(false);
    }
  }, [reportError]);

  useEffect(() => {
    stripBootstrapTokenFromUrl();
    void refreshState(null);
    // Initial boot load only; refreshState tracks subsequent selections.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleViewChange = useCallback(
    (next: AppView) => {
      setView(next);
      if (next === "obligations" && !obligations) {
        void loadObligations();
      } else if (next === "doctor" && !doctor) {
        void loadDoctor();
      }
    },
    [doctor, loadDoctor, loadObligations, obligations]
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const active = document.activeElement as HTMLElement | null;
      const tag = active?.tagName ?? "";
      const isEditing =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        Boolean(active?.isContentEditable);

      if (event.key === "/" && !isEditing && !createOpen && !cloneOpen) {
        event.preventDefault();
        setView("profiles");
        window.setTimeout(() => {
          searchInputRef.current?.focus();
        }, 0);
        return;
      }

      if (event.key === "Escape" && confirmDeleteOpen) {
        setConfirmDeleteOpen(false);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [cloneOpen, confirmDeleteOpen, createOpen]);

  const handleSelectProfile = useCallback(
    (name: string) => {
      setConfirmDeleteOpen(false);
      setSelectedName(name);
      void loadDetail(name);
    },
    [loadDetail]
  );

  const handleCreateProfile = async (payload: CreateProfilePayload) => {
    const created = await apiFetch<ProfileDetail>("/api/profiles", {
      method: "POST",
      body: payload,
    });
    toast({
      body: `Provisioned isolated sandbox "${created.manifest.name}".`,
      type: "info",
    });
    await refreshState(created.manifest.name);
  };

  const handleCloneProfile = async (
    source: string,
    payload: CloneProfilePayload
  ) => {
    const cloned = await apiFetch<ProfileDetail>(
      `/api/profiles/${encodeURIComponent(source)}/clone`,
      {
        method: "POST",
        body: payload,
      }
    );
    toast({
      body: `Cloned sandbox "${source}" to "${cloned.manifest.name}".`,
      type: "info",
    });
    await refreshState(cloned.manifest.name);
  };

  const handleLaunch = async (name: string, target: TargetKind) => {
    setActionBusy(`launch-${target}`);
    try {
      const res = await apiFetch<{
        profile: string;
        target: string;
        already_running?: boolean;
        pid?: number;
        pids?: number[];
      }>(`/api/profiles/${encodeURIComponent(name)}/launch`, {
        method: "POST",
        body: { target },
      });
      toast({
        body: res.already_running
          ? `${name} (${target.toUpperCase()}) is already running.`
          : `Launched ${name} (${target.toUpperCase()}) at PID ${res.pid ?? "started"}.`,
        type: "info",
      });
      await refreshState(name);
    } catch (err) {
      reportError(err, `Failed to launch ${name}.`);
    } finally {
      setActionBusy(null);
    }
  };

  const handleStop = async (name: string) => {
    setActionBusy("stop");
    try {
      await apiFetch(`/api/profiles/${encodeURIComponent(name)}/stop`, {
        method: "POST",
        body: { target: "all" },
      });
      toast({ body: `Stopped processes for "${name}".`, type: "info" });
      await refreshState(name);
    } catch (err) {
      reportError(err, `Failed to stop ${name}.`);
    } finally {
      setActionBusy(null);
    }
  };

  const handleRepair = async (name: string) => {
    setActionBusy("repair");
    try {
      await apiFetch(`/api/profiles/${encodeURIComponent(name)}/repair`, {
        method: "POST",
        body: {},
      });
      toast({
        body: `Reconciled permissions and locks for "${name}".`,
        type: "info",
      });
      await refreshState(name);
    } catch (err) {
      reportError(err, `Failed to repair ${name}.`);
    } finally {
      setActionBusy(null);
    }
  };

  const handleToggleLauncher = async (
    name: string,
    target: TargetKind,
    remove: boolean
  ) => {
    setActionBusy("launcher");
    try {
      await apiFetch(`/api/profiles/${encodeURIComponent(name)}/launcher`, {
        method: "POST",
        body: { action: remove ? "remove" : "build", target },
      });
      toast({
        body: remove
          ? `Removed ${target.toUpperCase()} desktop launcher for "${name}".`
          : `Built macOS .app launcher for "${name}" (${target.toUpperCase()}).`,
        type: "info",
      });
      await refreshState(name);
    } catch (err) {
      reportError(err, "Launcher action failed.");
    } finally {
      setActionBusy(null);
    }
  };

  const handleSavePolicy = async (
    name: string,
    payload: UpdateProfilePayload
  ) => {
    setActionBusy("save");
    try {
      await apiFetch<ProfileDetail>(
        `/api/profiles/${encodeURIComponent(name)}`,
        {
          method: "PATCH",
          body: payload,
        }
      );
      toast({
        body: `Saved isolation policy for "${name}".`,
        type: "info",
      });
      await refreshState(name);
    } catch (err) {
      reportError(err, "Failed to update profile policy.");
    } finally {
      setActionBusy(null);
    }
  };

  const handleDeleteProfile = async (name: string, forceStop: boolean) => {
    setActionBusy("delete");
    try {
      await apiFetch(`/api/profiles/${encodeURIComponent(name)}`, {
        method: "DELETE",
        body: { force_stop: forceStop },
      });
      setConfirmDeleteOpen(false);
      toast({ body: `Deleted sandbox profile "${name}".`, type: "info" });
      await refreshState(null);
    } catch (err) {
      reportError(err, `Failed to delete "${name}".`);
    } finally {
      setActionBusy(null);
    }
  };

  const profiles = overview?.profiles ?? [];
  const targets = overview?.targets ?? null;

  return (
    <>
      <AppShell
        height="fill"
        variant="elevated"
        contentPadding={0}
        topNav={
          <TopBar
            version={overview?.server.version ?? "0.1.0"}
            root={overview?.root ?? ""}
            view={view}
            profileCount={profiles.length}
            targets={targets}
            themeSlug={themeSlug}
            resolvedMode={resolvedMode}
            onViewChange={handleViewChange}
            onThemeChange={onThemeChange}
            onToggleColorMode={onToggleColorMode}
            onOpenCreate={() => setCreateOpen(true)}
          />
        }
        sideNav={
          view === "profiles" ? (
            <ProfilesSideRail
              profiles={profiles}
              selectedName={selectedName}
              searchQuery={searchQuery}
              runtimeFilter={runtimeFilter}
              searchInputRef={searchInputRef}
              onSearchChange={setSearchQuery}
              onRuntimeFilterChange={setRuntimeFilter}
              onSelectProfile={handleSelectProfile}
            />
          ) : undefined
        }
        mobileNav={view === "profiles" ? { breakpoint: "md" } : false}
      >
        {view === "profiles" ? (
          <ProfilesDetailPane
            profiles={profiles}
            detail={detail}
            targets={targets}
            detailLoading={detailLoading}
            actionBusy={actionBusy}
            confirmDeleteOpen={confirmDeleteOpen}
            onConfirmDeleteOpenChange={setConfirmDeleteOpen}
            onOpenCreate={() => setCreateOpen(true)}
            onOpenClone={() => setCloneOpen(true)}
            onLaunch={handleLaunch}
            onStop={handleStop}
            onRepair={handleRepair}
            onToggleLauncher={handleToggleLauncher}
            onSavePolicy={handleSavePolicy}
            onDeleteProfile={handleDeleteProfile}
          />
        ) : view === "obligations" ? (
          <ObligationsStage
            report={obligations}
            loading={obligationsLoading}
            onRefresh={() => void loadObligations()}
          />
        ) : (
          <DoctorStage
            doctor={doctor}
            loading={doctorLoading}
            onRefresh={() => void loadDoctor()}
          />
        )}
      </AppShell>

      <CreateProfileDrawer
        isOpen={createOpen}
        onOpenChange={setCreateOpen}
        onCreate={handleCreateProfile}
      />

      <CloneProfileDrawer
        sourceName={detail?.manifest.name ?? null}
        sourceLabel={detail?.manifest.label ?? null}
        isOpen={cloneOpen}
        onOpenChange={setCloneOpen}
        onClone={handleCloneProfile}
      />
    </>
  );
}

export default function App() {
  const [themeSlug, setThemeSlug] = useState<ThemeSlug>(readStoredTheme);
  const [colorMode, setColorMode] = useState<"light" | "dark">(readStoredMode);

  const resolvedMode: "light" | "dark" =
    themeSlug === "gothic" ? "dark" : colorMode;

  useEffect(() => {
    document.documentElement.dataset.theme = resolvedMode;
  }, [resolvedMode]);

  const handleThemeChange = useCallback((slug: ThemeSlug) => {
    setThemeSlug(slug);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, slug);
    } catch {
      // Ignore storage failures.
    }
  }, []);

  const handleToggleColorMode = useCallback(() => {
    setColorMode((prev) => {
      const next = prev === "dark" ? "light" : "dark";
      try {
        localStorage.setItem(MODE_STORAGE_KEY, next);
      } catch {
        // Ignore storage failures.
      }
      return next;
    });
  }, []);

  return (
    <Theme theme={themes[themeSlug]} mode={resolvedMode}>
      <ToastViewport position="bottomEnd" maxVisible={4}>
        <ConsoleShell
          themeSlug={themeSlug}
          resolvedMode={resolvedMode}
          onThemeChange={handleThemeChange}
          onToggleColorMode={handleToggleColorMode}
        />
      </ToastViewport>
    </Theme>
  );
}
