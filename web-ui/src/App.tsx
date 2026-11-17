import { useCallback, useEffect, useRef, useState } from "react";
import { AppShell } from "@astryxdesign/core/AppShell";
import { Theme } from "@astryxdesign/core/theme";
import { ToastViewport, useToast } from "@astryxdesign/core/Toast";
import { defaultThemeSlug, themes, type ThemeSlug } from "./astryx-themes";
import {
  ApiClientError,
  apiFetch,
  pluralize,
  stripBootstrapTokenFromUrl,
} from "./api";
import { DoctorStage } from "./components/DoctorStage";
import { HandoffStage } from "./components/HandoffStage";
import { ObligationsStage } from "./components/ObligationsStage";
import {
  CloneProfileDrawer,
  CreateProfileDrawer,
  RenameProfileDrawer,
} from "./components/ProfileDialogs";
import {
  HOST_SELECTION_ID,
  ProfilesDetailPane,
  ProfilesSideRail,
} from "./components/ProfilesWorkspace";
import { TopBar } from "./components/TopBar";
import type {
  AppView,
  AutomationsMode,
  CloneProfilePayload,
  CreateProfilePayload,
  DoctorResponse,
  HandoffResponse,
  HealScreenResponse,
  ObligationsResponse,
  OverviewResponse,
  ProfileDetail,
  ProfileFilter,
  RenameProfilePayload,
  ReturnHostSwitchResponse,
  SwitchProfileResponse,
  SyncProfileResponse,
  TargetKind,
  UpdateProfilePayload,
} from "./types";

const THEME_STORAGE_KEY = "agyp-astryx-theme-v2";
const MODE_STORAGE_KEY = "agyp-color-scheme-v2";

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
  return "dark";
}

interface ConsoleShellProps {
  themeSlug: ThemeSlug;
  isDarkOnlyTheme: boolean;
  resolvedMode: "light" | "dark";
  onThemeChange: (slug: ThemeSlug) => void;
  onToggleColorMode: () => void;
}

function ConsoleShell({
  themeSlug,
  isDarkOnlyTheme,
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
  const [renameOpen, setRenameOpen] = useState(false);

  const [obligations, setObligations] = useState<ObligationsResponse | null>(null);
  const [obligationsLoading, setObligationsLoading] = useState(false);
  const [doctor, setDoctor] = useState<DoctorResponse | null>(null);
  const [doctorLoading, setDoctorLoading] = useState(false);
  const [handoff, setHandoff] = useState<HandoffResponse | null>(null);
  const [handoffLoading, setHandoffLoading] = useState(false);
  const [handoffSource, setHandoffSource] = useState<string>("host");
  const [syncBusy, setSyncBusy] = useState<string | null>(null);
  const [handoffError, setHandoffError] = useState<string | null>(null);
  const [handoffTarget, setHandoffTarget] = useState<string | null>(null);
  const lastVisibilityRefreshRef = useRef<number>(0);

  const reportError = useCallback(
    (err: unknown, fallback: string) => {
      if (err instanceof ApiClientError) {
        const detailText = err.remediation
          ? `${err.message.replace(/\.$/, "")}. ${err.remediation}`
          : err.message;
        toast({ body: detailText, type: "error" });
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
        if (nextSelected === HOST_SELECTION_ID) {
          setSelectedName(HOST_SELECTION_ID);
          setDetail(null);
          return;
        }
        if (names.length === 0) {
          setSelectedName(HOST_SELECTION_ID);
          setDetail(null);
          return;
        }
        if (!nextSelected || !names.includes(nextSelected)) {
          nextSelected = names[0] ?? HOST_SELECTION_ID;
        }
        setSelectedName(nextSelected);
        if (nextSelected && nextSelected !== HOST_SELECTION_ID) {
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

  const loadHandoff = useCallback(
    async (sourceOverride?: string) => {
      const effectiveSource = sourceOverride ?? handoffSource;
      setHandoffLoading(true);
      setHandoffError(null);
      try {
        const data = await apiFetch<HandoffResponse>(
          `/api/handoff?limit=10&source=${encodeURIComponent(effectiveSource)}`
        );
        setHandoff(data);
      } catch (err) {
        const msg =
          err instanceof Error ? err.message : "Failed to load conversation handoff.";
        setHandoffError(msg);
        reportError(err, "Failed to load conversation handoff.");
      } finally {
        setHandoffLoading(false);
      }
    },
    [handoffSource, reportError]
  );

  const handleSelectHandoffSource = useCallback(
    (nextSource: string) => {
      setHandoffSource(nextSource);
      void loadHandoff(nextSource);
    },
    [loadHandoff]
  );

  const handleSyncProfile = useCallback(
    async (
      name: string,
      restart: boolean,
      automationsMode: AutomationsMode = "paused"
    ) => {
      setSyncBusy("sync");
      setHandoffError(null);
      const fromSrc = handoffSource === name ? "host" : handoffSource;
      try {
        const res = await apiFetch<SyncProfileResponse>(
          `/api/profiles/${encodeURIComponent(name)}/sync`,
          {
            method: "POST",
            body: {
              restart,
              include_handoff: true,
              include_sessions: true,
              automations_mode: automationsMode,
              from_source: fromSrc,
            },
          }
        );
        const autoCount = res.sync.automations_synced ?? 0;
        const autoEnabled = res.sync.automations_enabled ?? 0;
        const totalSessions = res.sync.sync_state.sessions_count ?? 0;
        const autoState =
          automationsMode === "strip"
            ? "stripped"
            : autoEnabled > 0
              ? `${autoEnabled} active`
              : "paused";
        toast({
          body: `Synced ${pluralize(
            res.sync.projects_synced,
            "project"
          )}, ${pluralize(totalSessions, "session")}, and ${pluralize(
            autoCount,
            "automation"
          )} (${autoState}) into ${name}.`,
          type: "info",
        });
        await refreshState(name);
        if (handoff) {
          void loadHandoff();
        }
      } catch (err) {
        const msg =
          err instanceof Error ? err.message : "Failed to sync profile setup.";
        setHandoffError(msg);
        reportError(err, "Failed to sync profile setup.");
      } finally {
        setSyncBusy(null);
      }
    },
    [handoff, handoffSource, loadHandoff, refreshState, reportError, toast]
  );

  const handleSwitchProfile = useCallback(
    async (name: string) => {
      setSyncBusy("switch");
      setHandoffError(null);
      const fromSrc = handoffSource === name ? "host" : handoffSource;
      try {
        const res = await apiFetch<SwitchProfileResponse>(
          `/api/profiles/${encodeURIComponent(name)}/switch`,
          {
            method: "POST",
            body: {
              automations_mode: "active",
              from_source: fromSrc,
              include_sessions: true,
              copy_prompt: true,
              launch: true,
            },
          }
        );
        const enabled = res.sync.automations_enabled ?? 0;
        const totalSessions = res.sync.sync_state.sessions_count ?? 0;
        toast({
          body: `Switched quota onto ${name} (${pluralize(
            totalSessions,
            "clickable session"
          )}, ${pluralize(enabled, "automation")} active${
            res.switch.prompt_copied ? ", prompt copied" : ""
          }).`,
          type: "info",
        });
        if (res.switch.git_status?.dirty) {
          toast({
            body: `Uncommitted edits detected in ${res.switch.git_status.workspace} (${res.switch.git_status.modified_count} modified).`,
            type: "info",
          });
        }
        await refreshState(name);
        if (handoff) {
          void loadHandoff();
        }
      } catch (err) {
        reportError(err, `Failed to switch quota onto ${name}.`);
      } finally {
        setSyncBusy(null);
      }
    },
    [handoff, handoffSource, loadHandoff, refreshState, reportError, toast]
  );

  const handleReturnToHost = useCallback(
    async (fromProfile: string) => {
      setSyncBusy("return-host");
      setHandoffError(null);
      try {
        const res = await apiFetch<ReturnHostSwitchResponse>(
          "/api/profiles/host/switch",
          {
            method: "POST",
            body: {
              from_source: fromProfile,
              include_sessions: true,
              copy_prompt: true,
              launch: true,
            },
          }
        );
        const hostEmail = res.host_account?.email ?? "Main Antigravity";
        const mergedCount = res.sessions?.synced_sessions ?? 0;
        toast({
          body: `Returned quota to ${hostEmail} (${pluralize(
            mergedCount,
            "session"
          )} merged, ${fromProfile} automations paused${
            res.switch.prompt_copied ? ", prompt copied" : ""
          }).`,
          type: "info",
        });
        if (res.switch.git_status?.dirty) {
          toast({
            body: `Uncommitted edits detected in ${res.switch.git_status.workspace} (${res.switch.git_status.modified_count} modified).`,
            type: "info",
          });
        }
        await refreshState();
        if (handoff) {
          void loadHandoff();
        }
      } catch (err) {
        reportError(err, `Failed to return quota from ${fromProfile} to Host.`);
      } finally {
        setSyncBusy(null);
      }
    },
    [handoff, loadHandoff, refreshState, reportError, toast]
  );

  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.visibilityState !== "visible") {
        return;
      }
      const now = Date.now();
      if (now - lastVisibilityRefreshRef.current < 3000) {
        return;
      }
      lastVisibilityRefreshRef.current = now;
      if (view === "profiles") {
        void refreshState();
      } else if (view === "handoff") {
        void loadHandoff();
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [loadHandoff, refreshState, view]);

  const handleViewChange = useCallback(
    (next: AppView) => {
      setView(next);
      if (next === "handoff" && !handoff) {
        void loadHandoff();
      } else if (next === "obligations" && !obligations) {
        void loadObligations();
      } else if (next === "doctor" && !doctor) {
        void loadDoctor();
      }
    },
    [doctor, handoff, loadDoctor, loadHandoff, loadObligations, obligations]
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && confirmDeleteOpen) {
        setConfirmDeleteOpen(false);
        return;
      }

      const active = document.activeElement as HTMLElement | null;
      const tag = active?.tagName ?? "";
      const isEditing =
        tag === "INPUT" ||
        tag === "TEXTAREA" ||
        tag === "SELECT" ||
        Boolean(active?.isContentEditable);

      if (
        isEditing ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey ||
        createOpen ||
        cloneOpen ||
        renameOpen ||
        confirmDeleteOpen
      ) {
        return;
      }

      if (event.key === "/") {
        event.preventDefault();
        setView("profiles");
        if (searchInputRef.current) {
          searchInputRef.current.focus();
        } else {
          window.setTimeout(() => {
            searchInputRef.current?.focus();
          }, 0);
        }
        return;
      }

      if (event.key === "n") {
        event.preventDefault();
        setCreateOpen(true);
        return;
      }

      if (event.key === "r") {
        event.preventDefault();
        if (view === "profiles") {
          void refreshState();
        } else if (view === "handoff") {
          void loadHandoff();
        } else if (view === "obligations") {
          void loadObligations();
        } else {
          void loadDoctor();
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    cloneOpen,
    confirmDeleteOpen,
    createOpen,
    loadDoctor,
    loadObligations,
    refreshState,
    renameOpen,
    view,
  ]);

  const handleSelectHost = useCallback(() => {
    setConfirmDeleteOpen(false);
    setSelectedName(HOST_SELECTION_ID);
  }, []);

  const handleSelectProfile = useCallback(
    (name: string) => {
      setConfirmDeleteOpen(false);
      if (name === HOST_SELECTION_ID) {
        setSelectedName(HOST_SELECTION_ID);
        return;
      }
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
      body: `Created profile ${created.manifest.name}.`,
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
      body: `Cloned ${source} to ${cloned.manifest.name}.`,
      type: "info",
    });
    await refreshState(cloned.manifest.name);
  };

  const handleRenameProfile = async (
    source: string,
    payload: RenameProfilePayload
  ) => {
    const renamed = await apiFetch<ProfileDetail>(
      `/api/profiles/${encodeURIComponent(source)}/rename`,
      {
        method: "POST",
        body: payload,
      }
    );
    toast({
      body: `Renamed ${source} to ${renamed.manifest.name}.`,
      type: "info",
    });
    await refreshState(renamed.manifest.name);
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
          : `Started ${name} (${target.toUpperCase()}, PID ${res.pid ?? "active"}).`,
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
      toast({ body: `Stopped ${name}.`, type: "info" });
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
        body: `Repaired locks and permissions for ${name}.`,
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
          ? `Removed ${target.toUpperCase()} launcher for ${name}.`
          : `Built ${target.toUpperCase()} .app launcher for ${name}.`,
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
        body: `Saved policy for ${name}.`,
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
      toast({ body: `Deleted profile ${name}.`, type: "info" });
      await refreshState(null);
    } catch (err) {
      reportError(err, `Failed to delete ${name}.`);
    } finally {
      setActionBusy(null);
    }
  };

  const handleHealScreen = async () => {
    setActionBusy("heal");
    try {
      const res = await apiFetch<HealScreenResponse>("/api/heal", {
        method: "POST",
        body: { scope: "all", target: "all", deep: false },
      });
      const gpuCount = res.recycled_gpu_pids.length;
      const cacheCount = res.cleared_shader_caches.length;
      toast({
        body: `Healed Antigravity compositor (${gpuCount} GPU ${pluralize(gpuCount, "helper")}, ${cacheCount} shader ${pluralize(cacheCount, "cache")} cleared) with zero sessions stopped.`,
        type: "info",
      });
      await refreshState(selectedName);
    } catch (err) {
      reportError(err, "Failed to heal Antigravity screen.");
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
            hostAccount={overview?.host_account ?? null}
            hostRuntime={overview?.host_runtime ?? null}
            themeSlug={themeSlug}
            isDarkOnlyTheme={isDarkOnlyTheme}
            resolvedMode={resolvedMode}
            healBusy={actionBusy === "heal"}
            onViewChange={handleViewChange}
            onThemeChange={onThemeChange}
            onToggleColorMode={onToggleColorMode}
            onHealScreen={() => void handleHealScreen()}
            onOpenCreate={() => setCreateOpen(true)}
          />
        }
        sideNav={
          view === "profiles" ? (
            <ProfilesSideRail
              profiles={profiles}
              hostAccount={overview?.host_account ?? null}
              hostRuntime={overview?.host_runtime ?? null}
              selectedName={selectedName}
              searchQuery={searchQuery}
              runtimeFilter={runtimeFilter}
              searchInputRef={searchInputRef}
              onSearchChange={setSearchQuery}
              onRuntimeFilterChange={setRuntimeFilter}
              onSelectHost={handleSelectHost}
              onSelectProfile={handleSelectProfile}
            />
          ) : undefined
        }
        mobileNav={view === "profiles" ? { breakpoint: "md" } : false}
      >
        {view === "profiles" ? (
          <ProfilesDetailPane
            selectedName={selectedName}
            hostAccount={overview?.host_account ?? null}
            hostRuntime={overview?.host_runtime ?? null}
            flow={overview?.flow ?? null}
            syncBusy={syncBusy}
            onSelectHost={handleSelectHost}
            onSync={handleSyncProfile}
            onSwitch={handleSwitchProfile}
            onReturnHost={handleReturnToHost}
            onOpenHandoff={() => handleViewChange("handoff")}
            profiles={profiles}
            detail={detail}
            targets={targets}
            detailLoading={detailLoading}
            actionBusy={actionBusy}
            confirmDeleteOpen={confirmDeleteOpen}
            onConfirmDeleteOpenChange={setConfirmDeleteOpen}
            onOpenCreate={() => setCreateOpen(true)}
            onOpenClone={() => setCloneOpen(true)}
            onOpenRename={() => setRenameOpen(true)}
            onLaunch={handleLaunch}
            onStop={handleStop}
            onRepair={handleRepair}
            onToggleLauncher={handleToggleLauncher}
            onSavePolicy={handleSavePolicy}
            onDeleteProfile={handleDeleteProfile}
          />
        ) : view === "handoff" ? (
          <HandoffStage
            handoff={handoff}
            hostAccount={overview?.host_account ?? null}
            hostRuntime={overview?.host_runtime ?? null}
            profiles={profiles}
            selectedSource={handoffSource}
            selectedProfile={handoffTarget}
            loading={handoffLoading}
            syncBusy={syncBusy}
            errorMessage={handoffError}
            onRefresh={() => void loadHandoff()}
            onSelectSource={handleSelectHandoffSource}
            onSelectProfile={setHandoffTarget}
            onSyncProfile={handleSyncProfile}
            onSwitchProfile={handleSwitchProfile}
            onReturnHost={handleReturnToHost}
            onOpenCreate={() => setCreateOpen(true)}
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

      <RenameProfileDrawer
        sourceName={detail?.manifest.name ?? null}
        sourceLabel={detail?.manifest.label ?? null}
        detectedEmail={detail?.account?.email ?? null}
        isRunning={
          detail
            ? detail.runtime.hub.state === "running" ||
              detail.runtime.ide.state === "running"
            : false
        }
        isOpen={renameOpen}
        onOpenChange={setRenameOpen}
        onRename={handleRenameProfile}
      />
    </>
  );
}

export default function App() {
  const [themeSlug, setThemeSlug] = useState<ThemeSlug>(readStoredTheme);
  const [colorMode, setColorMode] = useState<"light" | "dark">(readStoredMode);

  const isDarkOnlyTheme = themeSlug === "gothic-studio" || themeSlug === "gothic";
  const resolvedMode: "light" | "dark" = isDarkOnlyTheme ? "dark" : colorMode;

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
          isDarkOnlyTheme={isDarkOnlyTheme}
          resolvedMode={resolvedMode}
          onThemeChange={handleThemeChange}
          onToggleColorMode={handleToggleColorMode}
        />
      </ToastViewport>
    </Theme>
  );
}
