import { useEffect, useMemo, useState, type RefObject } from "react";
import { Avatar, AvatarStatusDot } from "@astryxdesign/core/Avatar";
import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { Code } from "@astryxdesign/core/Code";
import { Dialog, DialogHeader } from "@astryxdesign/core/Dialog";
import { Divider } from "@astryxdesign/core/Divider";
import { type DropdownMenuOption } from "@astryxdesign/core/DropdownMenu";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { FormLayout } from "@astryxdesign/core/FormLayout";
import { Grid } from "@astryxdesign/core/Grid";
import { Heading } from "@astryxdesign/core/Heading";
import { useClipboard } from "@astryxdesign/core/hooks";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { IconButton } from "@astryxdesign/core/IconButton";
import { Layout, LayoutContent, LayoutHeader } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { MoreMenu } from "@astryxdesign/core/MoreMenu";
import {
  SegmentedControl,
  SegmentedControlItem,
} from "@astryxdesign/core/SegmentedControl";
import { Selector } from "@astryxdesign/core/Selector";
import {
  SideNav,
  SideNavHeading,
  SideNavSection,
} from "@astryxdesign/core/SideNav";
import { StackItem } from "@astryxdesign/core/Stack";
import { StatusDot, type StatusDotVariant } from "@astryxdesign/core/StatusDot";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { VStack } from "@astryxdesign/core/VStack";
import {
  ACCENT_PRESETS,
  computeCombinedState,
  formatAuthMode,
  formatBytes,
  formatLinkPolicy,
  formatRuntimeState,
  formatTargetPidSummary,
  pluralize,
} from "../api";
import { Token } from "@astryxdesign/core/Token";
import type {
  AuthMode,
  AutomationsMode,
  HostAccountInfo,
  HostRuntimeInfo,
  LinkPolicy,
  ProfileDetail,
  ProfileFilter,
  ProfileSummary,
  QuotaFlowInfo,
  RuntimeStateType,
  TargetInfo,
  TargetKind,
  TargetRuntime,
  UpdateProfilePayload,
} from "../types";

export const HOST_SELECTION_ID = "__host__";

function runtimeDotVariant(state: RuntimeStateType): StatusDotVariant {
  if (state === "running") {
    return "success";
  }
  if (state === "stale-lock") {
    return "warning";
  }
  return "neutral";
}

function renderRuntimeEndState(state: RuntimeStateType) {
  if (state === "running") {
    return <Badge variant="success" label="Running" />;
  }
  if (state === "stale-lock") {
    return <Badge variant="warning" label="Stale lock" />;
  }
  return (
    <Text type="supporting" color="secondary">
      Stopped
    </Text>
  );
}

export interface ProfilesSideRailProps {
  profiles: ProfileSummary[];
  hostAccount?: HostAccountInfo | null;
  hostRuntime?: HostRuntimeInfo | null;
  selectedName: string | null;
  searchQuery: string;
  runtimeFilter: ProfileFilter;
  searchInputRef: RefObject<HTMLInputElement | null>;
  onSearchChange: (value: string) => void;
  onRuntimeFilterChange: (filter: ProfileFilter) => void;
  onSelectHost: () => void;
  onSelectProfile: (name: string) => void;
}

export function ProfilesSideRail({
  profiles,
  hostAccount = null,
  hostRuntime = null,
  selectedName,
  searchQuery,
  runtimeFilter,
  searchInputRef,
  onSearchChange,
  onRuntimeFilterChange,
  onSelectHost,
  onSelectProfile,
}: ProfilesSideRailProps) {
  const hostCombinedState: RuntimeStateType = hostRuntime
    ? computeCombinedState(hostRuntime)
    : "stopped";
  const hostCronCount =
    (hostRuntime?.hub.schedule_count ?? 0) +
    (hostRuntime?.ide.schedule_count ?? 0);

  const filteredProfiles = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return profiles.filter((p) => {
      const combined = computeCombinedState(p.runtime);
      if (runtimeFilter !== "all" && combined !== runtimeFilter) {
        return false;
      }
      if (!query) {
        return true;
      }
      return (
        p.manifest.name.toLowerCase().includes(query) ||
        p.manifest.label.toLowerCase().includes(query) ||
        (p.account?.email ?? "").toLowerCase().includes(query) ||
        p.manifest.default_target.toLowerCase().includes(query) ||
        p.manifest.link_policy.toLowerCase().includes(query)
      );
    });
  }, [profiles, runtimeFilter, searchQuery]);

  return (
    <SideNav
      aria-label="Antigravity workspaces"
      resizable={{ defaultWidth: 300, minWidth: 240, maxWidth: 420 }}
      header={
        <SideNavHeading
          heading="Profiles"
          subheading={`Host + ${pluralize(profiles.length, "backup")}`}
        />
      }
      topContent={
        <VStack gap={2} padding={2}>
          <TextInput
            ref={searchInputRef}
            label="Filter profiles"
            isLabelHidden
            type="search"
            placeholder="Filter profiles (/)"
            value={searchQuery}
            onChange={onSearchChange}
            hasClear
            startIcon={<Icon icon="search" size="sm" />}
          />
          <SegmentedControl
            label="Runtime state filter"
            size="sm"
            layout="fill"
            value={runtimeFilter}
            onChange={(value) => onRuntimeFilterChange(value as ProfileFilter)}
          >
            <SegmentedControlItem value="all" label="All" />
            <SegmentedControlItem value="running" label="Running" />
            <SegmentedControlItem value="stopped" label="Stopped" />
            <SegmentedControlItem value="stale-lock" label="Stale" />
          </SegmentedControl>
        </VStack>
      }
    >
      <SideNavSection title="Main Antigravity">
        <List density="balanced" hasDividers>
          <ListItem
            key={HOST_SELECTION_ID}
            isSelected={selectedName === HOST_SELECTION_ID}
            onClick={onSelectHost}
            startContent={
              <Avatar
                name={hostAccount?.email ?? "Main Antigravity"}
                size="sm"
                shape="rounded"
                tooltip={false}
              />
            }
            label={hostAccount?.email ?? "Main Antigravity"}
            description={`Host primary · ${pluralize(
              hostAccount?.projects_count ?? 0,
              "project"
            )}${
              hostCronCount > 0 ? ` · ${pluralize(hostCronCount, "cron")}` : ""
            }`}
            endContent={renderRuntimeEndState(hostCombinedState)}
          />
        </List>
      </SideNavSection>

      <SideNavSection title="Backup Profiles">
        {filteredProfiles.length === 0 ? (
          <VStack padding={3}>
            <Text type="supporting" color="secondary">
              {profiles.length === 0
                ? "No backup profiles provisioned yet."
                : "No backup profiles match this filter."}
            </Text>
          </VStack>
        ) : (
          <List density="balanced" hasDividers>
            {filteredProfiles.map((profile) => {
              const combined = computeCombinedState(profile.runtime);
              const backupAutoEnabled =
                profile.sync_state?.automations_enabled ?? 0;
              return (
                <ListItem
                  key={profile.manifest.name}
                  isSelected={selectedName === profile.manifest.name}
                  onClick={() => onSelectProfile(profile.manifest.name)}
                  startContent={
                    <Avatar
                      name={profile.manifest.label}
                      size="sm"
                      shape="rounded"
                      tooltip={false}
                    />
                  }
                  label={profile.manifest.label}
                  description={`${
                    profile.account?.email &&
                    !profile.manifest.label
                      .toLowerCase()
                      .includes(profile.account.email.toLowerCase())
                      ? profile.account.email
                      : profile.manifest.name
                  } · ${
                    backupAutoEnabled > 0 ? "Active quota" : "Standby"
                  } · ${formatBytes(profile.disk_bytes)}`}
                  endContent={renderRuntimeEndState(combined)}
                />
              );
            })}
          </List>
        )}
      </SideNavSection>
    </SideNav>
  );
}

interface HostPrimaryDetailViewProps {
  profiles: ProfileSummary[];
  hostAccount: HostAccountInfo | null;
  hostRuntime: HostRuntimeInfo | null;
  flow: QuotaFlowInfo | null;
  actionBusy: string | null;
  syncBusy: string | null;
  onOpenCreate: () => void;
  onSync: (
    name: string,
    restart: boolean,
    automationsMode?: AutomationsMode
  ) => Promise<void>;
  onSwitch: (name: string) => Promise<void>;
  onReturnHost: (fromProfile: string) => Promise<void>;
  onOpenHandoff: () => void;
}

function HostPrimaryDetailView({
  profiles,
  hostAccount,
  hostRuntime,
  flow,
  actionBusy,
  syncBusy,
  onOpenCreate,
  onSync,
  onSwitch,
  onReturnHost,
  onOpenHandoff,
}: HostPrimaryDetailViewProps) {
  const fallbackHub: TargetRuntime = {
    target: "hub",
    state: "stopped",
    pids: [],
    lock_files: [],
  };
  const fallbackIde: TargetRuntime = {
    target: "ide",
    state: "stopped",
    pids: [],
    lock_files: [],
  };
  const hubRt = hostRuntime?.hub ?? fallbackHub;
  const ideRt = hostRuntime?.ide ?? fallbackIde;
  const hostState = computeCombinedState({ hub: hubRt, ide: ideRt });
  const hostCronCount =
    (hubRt.schedule_count ?? 0) + (ideRt.schedule_count ?? 0);
  const hostAutoTotal = hostAccount?.automations_count ?? 0;
  const hostAutoEnabled = hostAccount?.automations_enabled ?? 0;
  const primaryBackup = profiles[0] ?? null;
  const activeBackupName = flow?.active_profiles[0] ?? null;
  const hostTitle = hostAccount?.email ?? "Main Antigravity";

  return (
    <Layout
      padding={6}
      height="fill"
      header={
        <LayoutHeader hasDivider>
          <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
            <HStack gap={3} vAlign="center" wrap="wrap">
              <Avatar
                name={hostTitle}
                size="lg"
                shape="rounded"
                tooltip={false}
                status={
                  <AvatarStatusDot
                    variant={
                      hostState === "running"
                        ? "success"
                        : hostState === "stale-lock"
                          ? "error"
                          : "neutral"
                    }
                    label={formatRuntimeState(hostState)}
                  />
                }
              />
              <VStack gap={1}>
                <HStack gap={2} vAlign="center" wrap="wrap">
                  <Heading level={1}>{hostTitle}</Heading>
                  {hostState === "running" ? (
                    <Badge variant="success" label="Running" />
                  ) : hostState === "stale-lock" ? (
                    <Badge variant="warning" label="Stale lock" />
                  ) : (
                    <HStack gap={1} vAlign="center">
                      <StatusDot variant="neutral" label="Stopped" />
                      <Text type="supporting" color="secondary">
                        Stopped
                      </Text>
                    </HStack>
                  )}
                </HStack>
                <HStack gap={1.5} vAlign="center" wrap="wrap">
                  <Code color="secondary">host</Code>
                  <Token size="sm" color="blue" label="Primary source" />
                  <Text type="supporting" color="secondary">
                    · {pluralize(hostAccount?.projects_count ?? 0, "project")} ·{" "}
                    {pluralize(hostAccount?.sessions_count ?? 0, "session")} ·{" "}
                    {pluralize(hostAutoTotal, "automation")} ({hostAutoEnabled}{" "}
                    enabled)
                  </Text>
                </HStack>
              </VStack>
            </HStack>

            <HStack gap={2} vAlign="center" wrap="wrap">
              {!primaryBackup ? (
                <Button
                  size="sm"
                  variant="primary"
                  label="New Profile"
                  onClick={onOpenCreate}
                />
              ) : (
                <>
                  {activeBackupName ? (
                    <Button
                      size="sm"
                      variant="primary"
                      label="Return to Host"
                      tooltip="Write backup handoff into Host, pause backup Automations, and copy resume prompt"
                      isDisabled={actionBusy !== null || syncBusy !== null}
                      isLoading={syncBusy === "return-host"}
                      onClick={() => void onReturnHost(activeBackupName)}
                    />
                  ) : (
                    <Button
                      size="sm"
                      variant="primary"
                      label="Take Over Quota"
                      tooltip={`Sync Host handoff and activate Automations on ${primaryBackup.manifest.name}`}
                      isDisabled={actionBusy !== null || syncBusy !== null}
                      isLoading={syncBusy === "switch"}
                      onClick={() => void onSwitch(primaryBackup.manifest.name)}
                    />
                  )}
                  <Button
                    size="sm"
                    variant="secondary"
                    label="Sync Standby"
                    tooltip={`Copy projects, settings, and paused Automations into ${primaryBackup.manifest.name}`}
                    isDisabled={actionBusy !== null || syncBusy !== null}
                    isLoading={syncBusy === "sync"}
                    onClick={() =>
                      void onSync(primaryBackup.manifest.name, false, "paused")
                    }
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    label="View Handoff"
                    onClick={onOpenHandoff}
                  />
                </>
              )}
            </HStack>
          </HStack>
        </LayoutHeader>
      }
      content={
        <LayoutContent>
          <VStack gap={4}>
            <Card padding={4}>
              <Grid columns={{ minWidth: 170, max: 4 }} gap={4}>
                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Hub Target
                  </Text>
                  <HStack gap={1.5} vAlign="center">
                    <StatusDot
                      variant={runtimeDotVariant(hubRt.state)}
                      label={formatRuntimeState(hubRt.state)}
                    />
                    <Text weight="semibold">
                      {formatRuntimeState(hubRt.state)}
                    </Text>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {formatTargetPidSummary(hubRt)}
                  </Text>
                </VStack>

                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    IDE Target
                  </Text>
                  <HStack gap={1.5} vAlign="center">
                    <StatusDot
                      variant={runtimeDotVariant(ideRt.state)}
                      label={formatRuntimeState(ideRt.state)}
                    />
                    <Text weight="semibold">
                      {formatRuntimeState(ideRt.state)}
                    </Text>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {formatTargetPidSummary(ideRt)}
                  </Text>
                </VStack>

                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Live Automations
                  </Text>
                  <HStack gap={1.5} vAlign="center">
                    <StatusDot
                      variant={hostCronCount > 0 ? "success" : "neutral"}
                      label={
                        hostCronCount > 0
                          ? "Active schedulers"
                          : "No live schedulers"
                      }
                    />
                    <Text weight="semibold" hasTabularNumbers>
                      {pluralize(hostCronCount, "cron runner")}
                    </Text>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {hostAutoEnabled} of {hostAutoTotal} enabled on disk
                  </Text>
                </VStack>

                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Active Quota Flow
                  </Text>
                  <HStack gap={1.5} vAlign="center">
                    <StatusDot
                      variant={
                        flow?.dual_automations_warning ? "warning" : "success"
                      }
                      label={flow?.mode ?? "host_primary"}
                    />
                    <Text weight="semibold">
                      {flow?.dual_automations_warning
                        ? "Dual crons"
                        : activeBackupName
                          ? `Backup (${activeBackupName})`
                          : "Host primary"}
                    </Text>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {pluralize(
                      flow?.standby_profiles.length ?? 0,
                      "standby profile"
                    )}
                  </Text>
                </VStack>
              </Grid>
            </Card>

            <Grid columns={{ minWidth: 340, max: 2 }} gap={4}>
              <Card padding={5}>
                <VStack gap={3}>
                  <Heading level={2}>Quota and Automation Flow</Heading>
                  <Text type="supporting" color="secondary">
                    {flow?.summary ??
                      "Main Antigravity serves as your primary workspace and customization source."}
                  </Text>
                  <MetadataList
                    columns={1}
                    label={{ position: "start", width: 140 }}
                  >
                    <MetadataListItem label="1. Primary Host">
                      Work in Main Antigravity while Sync Standby copies
                      projects, clickable sidebar sessions, worktrees, and
                      paused Automations into your backup profile.
                    </MetadataListItem>
                    <MetadataListItem label="2. Quota Takeover">
                      Click Take Over Quota on a backup profile to sync SQLite
                      session trajectories, rebuild the Hub sidebar index,
                      enable Automations, and launch.
                    </MetadataListItem>
                    <MetadataListItem label="3. Weekly Return">
                      Click Return to Host to merge new backup sessions back
                      into Main Antigravity, update HANDOFF_CONTEXT.md, and
                      reset backup Automations to paused standby.
                    </MetadataListItem>
                  </MetadataList>
                </VStack>
              </Card>

              <Card padding={5}>
                <VStack gap={3}>
                  <Heading level={2}>Host Source Inventory</Heading>
                  <MetadataList>
                    <MetadataListItem label="Account">
                      {hostAccount?.email ?? "Unsigned"} (
                      {hostAccount?.source ?? "unsigned"})
                    </MetadataListItem>
                    <MetadataListItem label="Projects">
                      {pluralize(hostAccount?.projects_count ?? 0, "project")}{" "}
                      configured
                    </MetadataListItem>
                    <MetadataListItem label="Sessions">
                      {pluralize(
                        hostAccount?.sessions_count ?? 0,
                        "clickable session"
                      )}
                    </MetadataListItem>
                    <MetadataListItem label="Automations">
                      {hostAutoTotal > 0
                        ? `${pluralize(hostAutoTotal, "automation")} (${hostAutoEnabled} enabled, ${pluralize(hostCronCount, "live runner")})`
                        : "0 configured"}
                    </MetadataListItem>
                    <MetadataListItem label="Agents and Plugins">
                      {pluralize(hostAccount?.plugins_count ?? 0, "plugin")} ·{" "}
                      {pluralize(hostAccount?.agents_count ?? 0, "agent")} ·{" "}
                      {pluralize(hostAccount?.skills_count ?? 0, "skill")}
                    </MetadataListItem>
                    <MetadataListItem label="MCP and Handoff">
                      {hostAccount?.mcp_present ? "MCP ready" : "No MCP"} ·{" "}
                      {hostAccount?.hooks_present ? "Hooks active" : "No hooks"}{" "}
                      ·{" "}
                      {hostAccount?.handoff_present
                        ? "Return handoff ready"
                        : "No return handoff"}
                    </MetadataListItem>
                    <MetadataListItem label="Source Safety">
                      Host ~/.gemini stays unlocked during sync; Return to Host
                      merges new backup sessions and skips open locked threads.
                    </MetadataListItem>
                  </MetadataList>
                </VStack>
              </Card>
            </Grid>
          </VStack>
        </LayoutContent>
      }
    />
  );
}

export interface ProfilesDetailPaneProps {
  profiles: ProfileSummary[];
  selectedName: string | null;
  detail: ProfileDetail | null;
  targets: { hub: TargetInfo; ide: TargetInfo } | null;
  hostAccount?: HostAccountInfo | null;
  hostRuntime?: HostRuntimeInfo | null;
  flow?: QuotaFlowInfo | null;
  detailLoading: boolean;
  actionBusy: string | null;
  syncBusy?: string | null;
  confirmDeleteOpen: boolean;
  onConfirmDeleteOpenChange: (open: boolean) => void;
  onSelectHost: () => void;
  onOpenCreate: () => void;
  onOpenClone: () => void;
  onOpenRename: () => void;
  onSync: (name: string, restart: boolean, automationsMode?: AutomationsMode) => Promise<void>;
  onSwitch: (name: string) => Promise<void>;
  onReturnHost: (fromProfile: string) => Promise<void>;
  onOpenHandoff: () => void;
  onLaunch: (name: string, target: TargetKind) => Promise<void>;
  onStop: (name: string) => Promise<void>;
  onRepair: (name: string) => Promise<void>;
  onToggleLauncher: (
    name: string,
    target: TargetKind,
    remove: boolean
  ) => Promise<void>;
  onSavePolicy: (name: string, payload: UpdateProfilePayload) => Promise<void>;
  onDeleteProfile: (name: string, forceStop: boolean) => Promise<void>;
}

export function ProfilesDetailPane({
  profiles,
  selectedName,
  detail,
  targets,
  hostAccount = null,
  hostRuntime = null,
  flow = null,
  detailLoading,
  actionBusy,
  syncBusy = null,
  confirmDeleteOpen,
  onConfirmDeleteOpenChange,
  onSelectHost,
  onOpenCreate,
  onOpenClone,
  onOpenRename,
  onSync,
  onSwitch,
  onReturnHost,
  onOpenHandoff,
  onLaunch,
  onStop,
  onRepair,
  onToggleLauncher,
  onSavePolicy,
  onDeleteProfile,
}: ProfilesDetailPaneProps) {
  const [editLabel, setEditLabel] = useState("");
  const [editAccent, setEditAccent] = useState("#B45309");
  const [editTarget, setEditTarget] = useState<TargetKind>("hub");
  const [editLinkPolicy, setEditLinkPolicy] = useState<LinkPolicy>("minimal");
  const [editAuthMode, setEditAuthMode] = useState<AuthMode>("isolated-file");
  const [editKeepBg, setEditKeepBg] = useState(false);
  const [forceStopDelete, setForceStopDelete] = useState(false);
  const { copy, isCopied } = useClipboard({
    announce: "Copied profile root path",
  });
  const normalizedAccent = editAccent.trim().toUpperCase();
  const accentOptions = useMemo(() => {
    const options = ACCENT_PRESETS.map((preset) => ({
      value: preset.hex.toUpperCase(),
      label: preset.label,
      description: preset.hex.toUpperCase(),
    }));
    if (
      normalizedAccent &&
      !options.some((option) => option.value === normalizedAccent)
    ) {
      options.push({
        value: normalizedAccent,
        label: `Custom (${normalizedAccent})`,
        description: normalizedAccent,
      });
    }
    return options;
  }, [normalizedAccent]);

  useEffect(() => {
    if (!detail) {
      return;
    }
    setEditLabel(detail.manifest.label);
    setEditAccent(detail.manifest.accent);
    setEditTarget(detail.manifest.default_target);
    setEditLinkPolicy(detail.manifest.link_policy);
    setEditAuthMode(detail.manifest.auth_mode);
    setEditKeepBg(detail.manifest.keep_background_alive);
    setForceStopDelete(false);
  }, [detail]);

  if (selectedName === HOST_SELECTION_ID || profiles.length === 0) {
    return (
      <HostPrimaryDetailView
        profiles={profiles}
        hostAccount={hostAccount}
        hostRuntime={hostRuntime}
        flow={flow}
        actionBusy={actionBusy}
        syncBusy={syncBusy}
        onOpenCreate={onOpenCreate}
        onSync={onSync}
        onSwitch={onSwitch}
        onReturnHost={onReturnHost}
        onOpenHandoff={onOpenHandoff}
      />
    );
  }

  if (!detail) {
    return (
      <Layout
        padding={6}
        height="fill"
        content={
          <LayoutContent>
            <EmptyState
              headingLevel={2}
              title={detailLoading ? "Loading profile..." : "Select a profile"}
              description="Choose a profile from the list to inspect permissions, locks, and paths."
            />
          </LayoutContent>
        }
      />
    );
  }

  const combinedState = computeCombinedState(detail.runtime);
  const hasDefaultLauncher = detail.launchers[detail.manifest.default_target];
  const anyRunning = combinedState === "running";
  const hubInstalled = targets?.hub.installed ?? true;
  const ideInstalled = targets?.ide.installed ?? true;

  const defaultTarget = detail.manifest.default_target;
  const altTarget: TargetKind = defaultTarget === "hub" ? "ide" : "hub";
  const defaultInstalled = defaultTarget === "hub" ? hubInstalled : ideInstalled;
  const altInstalled = altTarget === "hub" ? hubInstalled : ideInstalled;
  const primaryLaunchLabel = defaultTarget === "hub" ? "Launch Hub" : "Launch IDE";
  const altLaunchLabel = altTarget === "hub" ? "Launch Hub" : "Launch IDE";
  const autoCount = detail.sync_state?.automations_count ?? 0;
  const autoEnabled = detail.sync_state?.automations_enabled ?? 0;
  const hostCombinedState: RuntimeStateType = hostRuntime
    ? computeCombinedState(hostRuntime)
    : "stopped";
  const hostCronCount =
    (hostRuntime?.hub.schedule_count ?? 0) +
    (hostRuntime?.ide.schedule_count ?? 0);
  const hostRootPid =
    hostRuntime?.hub.root_pids?.[0] ??
    hostRuntime?.ide.root_pids?.[0] ??
    hostRuntime?.hub.pids[0] ??
    hostRuntime?.ide.pids[0] ??
    null;

  const overflowItems: DropdownMenuOption[] = [
    ...(anyRunning
      ? [
          {
            id: "launch-alt",
            label: altLaunchLabel,
            isDisabled: !altInstalled || actionBusy !== null,
            onClick: () => void onLaunch(detail.manifest.name, altTarget),
          },
        ]
      : []),
    ...(autoEnabled > 0
      ? [
          {
            id: "return-host",
            label: "Return to Host",
            description:
              "Write backup handoff into Main Antigravity and pause backup Automations",
            isDisabled: actionBusy !== null || syncBusy !== null,
            onClick: () => void onReturnHost(detail.manifest.name),
          },
        ]
      : []),
    {
      id: "switch",
      label: "Take Over Quota",
      description: "Sync setup and handoff, enable Automations, and relaunch",
      isDisabled: actionBusy !== null || syncBusy !== null,
      onClick: () => void onSwitch(detail.manifest.name),
    },
    {
      id: "sync",
      label: "Sync Host Setup",
      description: hostAccount?.email
        ? `Copy setup and paused Automations from ${hostAccount.email}`
        : "Copy sanitized setup and Automations in paused standby",
      isDisabled: actionBusy !== null || syncBusy !== null,
      onClick: () => void onSync(detail.manifest.name, false, "paused"),
    },
    {
      id: "sync_restart",
      label: "Sync and Restart",
      description: "Re-sync setup and paused Automations, then relaunch target",
      isDisabled: actionBusy !== null || syncBusy !== null,
      onClick: () => void onSync(detail.manifest.name, true, "paused"),
    },
    {
      id: "sync_active",
      label: "Sync and Enable Automations",
      description: "Copy Host Automations enabled for active scheduled runs",
      isDisabled: actionBusy !== null || syncBusy !== null,
      onClick: () => void onSync(detail.manifest.name, true, "active"),
    },
    {
      id: "handoff",
      label: "View Host Handoff",
      description: "Inspect recent Host conversations and resume prompt",
      onClick: onOpenHandoff,
    },
    {
      id: "repair",
      label: "Repair Locks",
      icon: <Icon icon="wrench" size="sm" />,
      isDisabled: actionBusy !== null,
      onClick: () => void onRepair(detail.manifest.name),
    },
    {
      id: "rename",
      label: "Rename Profile",
      description: "Update slug or label while keeping OAuth login intact",
      isDisabled: actionBusy !== null || syncBusy !== null,
      onClick: onOpenRename,
    },
    {
      id: "clone",
      label: "Clone Profile",
      icon: <Icon icon="copy" size="sm" />,
      isDisabled: anyRunning || actionBusy !== null,
      onClick: onOpenClone,
    },
    {
      id: "launcher",
      label: hasDefaultLauncher
        ? "Remove .app Launcher"
        : "Build .app Launcher",
      isDisabled: actionBusy !== null,
      onClick: () =>
        void onToggleLauncher(
          detail.manifest.name,
          detail.manifest.default_target,
          hasDefaultLauncher
        ),
    },
    { type: "divider" },
    {
      id: "delete",
      label: "Delete Profile",
      variant: "destructive" as const,
      isDisabled: actionBusy !== null,
      onClick: () => onConfirmDeleteOpenChange(true),
    },
  ];

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSavePolicy(detail.manifest.name, {
      label: editLabel.trim() || detail.manifest.name,
      accent: editAccent,
      default_target: editTarget,
      link_policy: editLinkPolicy,
      auth_mode: editAuthMode,
      keep_background_alive: editKeepBg,
    });
  };

  return (
    <>
      <Layout
        padding={6}
        height="fill"
        header={
          <LayoutHeader hasDivider>
            <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
              <HStack gap={3} vAlign="center" wrap="wrap">
                <Avatar
                  name={detail.manifest.label}
                  size="lg"
                  shape="rounded"
                  tooltip={false}
                  status={
                    <AvatarStatusDot
                      variant={
                        combinedState === "running"
                          ? "success"
                          : combinedState === "stale-lock"
                            ? "error"
                            : "neutral"
                      }
                      label={formatRuntimeState(combinedState)}
                    />
                  }
                />
                <VStack gap={1}>
                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Heading level={1}>{detail.manifest.label}</Heading>
                    {combinedState === "running" ? (
                      <Badge variant="success" label="Running" />
                    ) : combinedState === "stale-lock" ? (
                      <Badge variant="warning" label="Stale lock" />
                    ) : (
                      <HStack gap={1} vAlign="center">
                        <StatusDot variant="neutral" label="Stopped" />
                        <Text type="supporting" color="secondary">
                          Stopped
                        </Text>
                      </HStack>
                    )}
                  </HStack>
                  <HStack gap={1.5} vAlign="center" wrap="wrap">
                    <Code color="secondary">{detail.manifest.name}</Code>
                    <Token
                      size="sm"
                      color={detail.account?.email ? "blue" : "gray"}
                      label={
                        detail.account?.email
                          ? detail.manifest.label
                              .toLowerCase()
                              .includes(detail.account.email.toLowerCase())
                            ? "OAuth verified"
                            : detail.account.email
                          : "Unsigned"
                      }
                    />
                    <Text type="supporting" color="secondary">
                      · {formatAuthMode(detail.manifest.auth_mode)} ·{" "}
                      {formatLinkPolicy(detail.manifest.link_policy)} · Created{" "}
                      <Timestamp
                        value={detail.manifest.created_at}
                        format="date"
                        timezoneID="UTC"
                      />{" "}
                      ·{" "}
                      {detail.manifest.last_launched_at ? (
                        <>
                          Last run{" "}
                          <Timestamp
                            value={detail.manifest.last_launched_at}
                            format="auto"
                          />
                        </>
                      ) : (
                        "Never launched"
                      )}
                    </Text>
                  </HStack>
                </VStack>
              </HStack>

              <HStack gap={2} vAlign="center">
                <Button
                  size="sm"
                  variant="primary"
                  label={primaryLaunchLabel}
                  isDisabled={!defaultInstalled || actionBusy !== null}
                  isLoading={actionBusy === `launch-${defaultTarget}`}
                  onClick={() =>
                    void onLaunch(detail.manifest.name, defaultTarget)
                  }
                />
                {anyRunning ? (
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={<Icon icon="stop" size="sm" />}
                    label="Stop"
                    isDisabled={actionBusy !== null}
                    isLoading={actionBusy === "stop"}
                    onClick={() => void onStop(detail.manifest.name)}
                  />
                ) : (
                  <Button
                    size="sm"
                    variant="secondary"
                    label={altLaunchLabel}
                    isDisabled={!altInstalled || actionBusy !== null}
                    isLoading={actionBusy === `launch-${altTarget}`}
                    onClick={() =>
                      void onLaunch(detail.manifest.name, altTarget)
                    }
                  />
                )}
                <Button
                  size="sm"
                  variant="secondary"
                  label="Sync Setup"
                  tooltip={
                    hostAccount?.email
                      ? `Sync sanitized setup and paused Automations from ${hostAccount.email}`
                      : "Sync sanitized host setup, Automations, and handoff"
                  }
                  isDisabled={actionBusy !== null || syncBusy !== null}
                  isLoading={syncBusy === "sync"}
                  onClick={() => void onSync(detail.manifest.name, false, "paused")}
                />
                <MoreMenu
                  label="More profile actions"
                  size="sm"
                  variant="secondary"
                  alignment="end"
                  isDisabled={actionBusy !== null}
                  items={overflowItems}
                />
              </HStack>
            </HStack>
          </LayoutHeader>
        }
        content={
          <LayoutContent>
            <VStack gap={4}>
              <Card padding={4}>
                <HStack hAlign="between" vAlign="center" gap={3} wrap="wrap">
                  <VStack gap={1}>
                    <HStack gap={2} vAlign="center" wrap="wrap">
                      <Text type="label" color="secondary">
                        Quota and Automation Flow
                      </Text>
                      {flow?.dual_automations_warning ? (
                        <Badge variant="warning" label="Dual crons" />
                      ) : autoEnabled > 0 ? (
                        <Token size="sm" color="blue" label="Backup active" />
                      ) : (
                        <Token size="sm" color="gray" label="Standby paused" />
                      )}
                    </HStack>
                    <HStack gap={1.5} vAlign="center" wrap="wrap">
                      <StatusDot
                        variant={runtimeDotVariant(hostCombinedState)}
                        label={`Main Antigravity ${formatRuntimeState(hostCombinedState)}`}
                      />
                      <Text weight="medium">
                        Main: {hostAccount?.email ?? "Unsigned"} (
                        {formatRuntimeState(hostCombinedState)}
                        {hostRootPid ? `, PID ${hostRootPid}` : ""}
                        {hostCronCount > 0
                          ? `, ${pluralize(hostCronCount, "cron")}`
                          : ""}
                        )
                      </Text>
                      <Text type="supporting" color="secondary">
                        · Backup:{" "}
                        {detail.account?.email ?? detail.manifest.label} (
                        {autoEnabled > 0
                          ? `${pluralize(autoEnabled, "automation")} active`
                          : `${pluralize(autoCount, "automation")} paused`}
                        )
                      </Text>
                    </HStack>
                    {flow?.dual_automations_warning ? (
                      <Text type="supporting" color="secondary">
                        Both Main Antigravity and {detail.manifest.name} have
                        active automations. Click Return to Host to pause backup
                        crons, or quit Main Antigravity while using backup quota.
                      </Text>
                    ) : null}
                  </VStack>
                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Button
                      size="sm"
                      variant="ghost"
                      label="Inspect Host"
                      onClick={onSelectHost}
                    />
                    {autoEnabled > 0 ? (
                      <Button
                        size="sm"
                        variant="primary"
                        label="Return to Host"
                        isDisabled={actionBusy !== null || syncBusy !== null}
                        isLoading={syncBusy === "return-host"}
                        onClick={() => void onReturnHost(detail.manifest.name)}
                      />
                    ) : (
                      <Button
                        size="sm"
                        variant="secondary"
                        label="Take Over Quota"
                        isDisabled={actionBusy !== null || syncBusy !== null}
                        isLoading={syncBusy === "switch"}
                        onClick={() => void onSwitch(detail.manifest.name)}
                      />
                    )}
                  </HStack>
                </HStack>
              </Card>

              <Card padding={4}>
                <Grid columns={{ minWidth: 170, max: 4 }} gap={4}>
                  <VStack gap={1}>
                    <Text type="label" color="secondary">
                      Hub Target
                    </Text>
                    <HStack gap={1.5} vAlign="center">
                      <StatusDot
                        variant={runtimeDotVariant(detail.runtime.hub.state)}
                        label={formatRuntimeState(detail.runtime.hub.state)}
                      />
                      <Text weight="semibold">
                        {formatRuntimeState(detail.runtime.hub.state)}
                      </Text>
                    </HStack>
                    <Text type="supporting" color="secondary" hasTabularNumbers>
                      {formatTargetPidSummary(detail.runtime.hub)}
                    </Text>
                  </VStack>

                  <VStack gap={1}>
                    <Text type="label" color="secondary">
                      IDE Target
                    </Text>
                    <HStack gap={1.5} vAlign="center">
                      <StatusDot
                        variant={runtimeDotVariant(detail.runtime.ide.state)}
                        label={formatRuntimeState(detail.runtime.ide.state)}
                      />
                      <Text weight="semibold">
                        {formatRuntimeState(detail.runtime.ide.state)}
                      </Text>
                    </HStack>
                    <Text type="supporting" color="secondary" hasTabularNumbers>
                      {formatTargetPidSummary(detail.runtime.ide)}
                    </Text>
                  </VStack>

                  <VStack gap={1}>
                    <Text type="label" color="secondary">
                      Disk Usage
                    </Text>
                    <Text weight="semibold" hasTabularNumbers>
                      {formatBytes(detail.disk_bytes)}
                    </Text>
                    <Text type="supporting" color="secondary">
                      Updated{" "}
                      <Timestamp
                        value={detail.manifest.updated_at}
                        format="auto"
                      />
                    </Text>
                  </VStack>

                  <VStack gap={1}>
                    <Text type="label" color="secondary">
                      HOME Isolation
                    </Text>
                    <HStack gap={1.5} vAlign="center">
                      <StatusDot
                        variant={
                          detail.isolation.zshenv_home_locked &&
                          detail.isolation.forbidden_symlinks_present.length ===
                            0
                            ? "success"
                            : "error"
                        }
                        label={
                          detail.isolation.zshenv_home_locked
                            ? "Locked (.zshenv)"
                            : "Unlocked"
                        }
                      />
                      <Text weight="semibold">
                        {detail.isolation.zshenv_home_locked
                          ? "Locked (.zshenv)"
                          : "Unlocked"}
                      </Text>
                    </HStack>
                    <Text type="supporting" color="secondary" hasTabularNumbers>
                      {detail.isolation.forbidden_symlinks_present.length}{" "}
                      forbidden ·{" "}
                      {pluralize(detail.isolation.active_symlinks.length, "link")}
                    </Text>
                  </VStack>
                </Grid>
              </Card>

              <Grid columns={{ minWidth: 340, max: 2 }} gap={4}>
                <Card padding={5}>
                  <VStack gap={4}>
                    <Heading level={2}>Sandbox Policy</Heading>
                    <form onSubmit={handleSave}>
                      <FormLayout direction="vertical">
                        <TextInput
                          label="Display Label"
                          value={editLabel}
                          onChange={setEditLabel}
                          isRequired
                        />
                        <Selector
                          label="Accent Color"
                          value={normalizedAccent}
                          onChange={setEditAccent}
                          options={accentOptions}
                        />
                        <Selector
                          label="Default Target"
                          value={editTarget}
                          onChange={(val) => setEditTarget(val as TargetKind)}
                          options={[
                            { value: "hub", label: "Antigravity Hub" },
                            { value: "ide", label: "Antigravity IDE" },
                          ]}
                        />
                        <Selector
                          label="Symlink Policy"
                          value={editLinkPolicy}
                          onChange={(val) =>
                            setEditLinkPolicy(val as LinkPolicy)
                          }
                          options={[
                            {
                              value: "none",
                              label: "None (zero host links)",
                            },
                            {
                              value: "minimal",
                              label: "Minimal (fonts and safe caches)",
                            },
                            {
                              value: "dev",
                              label: "Dev (toolchains and .agents)",
                            },
                          ]}
                        />
                        <Selector
                          label="Auth Storage"
                          value={editAuthMode}
                          onChange={(val) => setEditAuthMode(val as AuthMode)}
                          options={[
                            {
                              value: "isolated-file",
                              label: "Isolated file (per-sandbox token)",
                            },
                            {
                              value: "system-keychain",
                              label: "System keychain (macOS login)",
                            },
                          ]}
                        />
                        <Switch
                          label="Keep helper processes running after close"
                          value={editKeepBg}
                          onChange={(checked) => setEditKeepBg(checked)}
                        />
                        <HStack hAlign="end">
                          <Button
                            type="submit"
                            variant="primary"
                            label="Save Policy"
                            isLoading={actionBusy === "save"}
                            isDisabled={actionBusy !== null}
                          />
                        </HStack>
                      </FormLayout>
                    </form>
                  </VStack>
                </Card>

                <Card padding={5}>
                  <VStack gap={4}>
                    <Heading level={2}>Filesystem Proof</Heading>

                    <VStack gap={2}>
                      <Heading level={3}>File Permissions</Heading>
                      <MetadataList
                        columns={1}
                        label={{ position: "start", width: 155 }}
                      >
                        <MetadataListItem label="Profile root">
                          <Code>
                            {detail.isolation.permissions.profile_dir ?? "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="App data">
                          <Code>
                            {detail.isolation.permissions.data_dir ?? "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="Sandbox HOME">
                          <Code>
                            {detail.isolation.permissions.sandbox_home ?? "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="Shell lock (.zshenv)">
                          <Code>
                            {detail.isolation.permissions.zshenv_file ?? "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="OAuth token">
                          <Code>
                            {detail.isolation.permissions.oauth_token_file ??
                              "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="MCP config">
                          <Code>
                            {detail.isolation.permissions.mcp_config_file ??
                              "--"}
                          </Code>
                        </MetadataListItem>
                        <MetadataListItem label="Handoff digest">
                          <Code>
                            {detail.isolation.permissions.handoff_file ?? "--"}
                          </Code>
                        </MetadataListItem>
                      </MetadataList>
                    </VStack>

                    <Divider />

                    <VStack gap={2}>
                      <Heading level={3}>Synced Setup</Heading>
                      <MetadataList>
                        <MetadataListItem label="Account">
                          {detail.account?.email ?? "Unsigned"} (
                          {detail.account?.source ?? "unsigned"})
                        </MetadataListItem>
                        <MetadataListItem label="Projects">
                          {detail.sync_state?.projects_count ?? 0} synced
                        </MetadataListItem>
                        <MetadataListItem label="Sessions">
                          {pluralize(
                            detail.sync_state?.sessions_count ?? 0,
                            "clickable session"
                          )}
                        </MetadataListItem>
                        <MetadataListItem label="Automations">
                          {autoCount > 0
                            ? `${pluralize(autoCount, "automation")} (${
                                autoEnabled > 0
                                  ? `${autoEnabled} active`
                                  : "paused standby"
                              })`
                            : "0 synced"}
                        </MetadataListItem>
                        <MetadataListItem label="Agents and Plugins">
                          {pluralize(detail.sync_state?.plugins_count ?? 0, "plugin")}{" "}
                          ·{" "}
                          {pluralize(detail.sync_state?.agents_count ?? 0, "agent")}{" "}
                          ·{" "}
                          {pluralize(detail.sync_state?.skills_count ?? 0, "skill")}
                        </MetadataListItem>
                        <MetadataListItem label="MCP and Handoff">
                          {detail.sync_state?.mcp_present ? "MCP ready" : "No MCP"}{" "}
                          ·{" "}
                          {detail.sync_state?.handoff_present
                            ? "Handoff ready"
                            : "No handoff"}
                        </MetadataListItem>
                      </MetadataList>
                    </VStack>

                    <Divider />

                    <VStack gap={2}>
                      <Heading level={3}>Sandbox Paths</Heading>
                      <MetadataList
                        columns={1}
                        label={{ position: "start", width: 135 }}
                      >
                        <MetadataListItem label="Root directory">
                          <HStack gap={1} vAlign="center">
                            <StackItem size="fill">
                              <Text maxLines={1}>
                                <Code>{detail.paths.profile_dir}</Code>
                              </Text>
                            </StackItem>
                            <IconButton
                              size="sm"
                              variant="ghost"
                              label={
                                isCopied ? "Copied" : "Copy profile root path"
                              }
                              tooltip="Copy root path"
                              icon={
                                <Icon
                                  icon={isCopied ? "check" : "copy"}
                                  size="sm"
                                />
                              }
                              onClick={() => void copy(detail.paths.profile_dir)}
                            />
                          </HStack>
                        </MetadataListItem>
                        <MetadataListItem label="Subdirectories">
                          <Code>./data · ./ide-data · ./home</Code>
                        </MetadataListItem>
                        <MetadataListItem label="Evidence">
                          <Text
                            type="supporting"
                            color="secondary"
                            hasTabularNumbers
                          >
                            {detail.evidence.evidence_id} ·{" "}
                            {detail.evidence.authority} (
                            {detail.evidence.confidence})
                          </Text>
                        </MetadataListItem>
                      </MetadataList>
                    </VStack>

                    <Divider />

                    <VStack gap={2}>
                      <Heading level={3}>Inspection Scope</Heading>
                      <List density="compact" hasDividers>
                        {detail.evidence.limitations.map((limitation, idx) => (
                          <ListItem
                            key={idx}
                            startContent={
                              <Icon icon="info" size="sm" color="secondary" />
                            }
                            label={limitation}
                          />
                        ))}
                      </List>
                    </VStack>
                  </VStack>
                </Card>
              </Grid>
            </VStack>
          </LayoutContent>
        }
      />

      <Dialog
        isOpen={confirmDeleteOpen}
        onOpenChange={onConfirmDeleteOpenChange}
        width={420}
        purpose="form"
      >
        <Layout
          header={
            <DialogHeader
              title={`Delete ${detail.manifest.label}?`}
              subtitle="Removes the profile directory, sandbox home, and saved tokens permanently."
              onOpenChange={onConfirmDeleteOpenChange}
            />
          }
          content={
            <LayoutContent>
              <CheckboxInput
                label="Stop running processes first"
                value={forceStopDelete}
                onChange={(checked) => setForceStopDelete(checked)}
              />
            </LayoutContent>
          }
          footer={
            <HStack gap={2} hAlign="end">
              <Button
                variant="ghost"
                label="Cancel"
                isDisabled={actionBusy !== null}
                onClick={() => onConfirmDeleteOpenChange(false)}
              />
              <Button
                variant="destructive"
                label="Delete Profile"
                isLoading={actionBusy === "delete"}
                onClick={() =>
                  void onDeleteProfile(detail.manifest.name, forceStopDelete)
                }
              />
            </HStack>
          }
        />
      </Dialog>
    </>
  );
}
