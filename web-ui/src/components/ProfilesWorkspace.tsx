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
  pluralize,
} from "../api";
import type {
  AuthMode,
  LinkPolicy,
  ProfileDetail,
  ProfileFilter,
  ProfileSummary,
  RuntimeStateType,
  TargetInfo,
  TargetKind,
  UpdateProfilePayload,
} from "../types";

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
  selectedName: string | null;
  searchQuery: string;
  runtimeFilter: ProfileFilter;
  searchInputRef: RefObject<HTMLInputElement | null>;
  onSearchChange: (value: string) => void;
  onRuntimeFilterChange: (filter: ProfileFilter) => void;
  onSelectProfile: (name: string) => void;
}

export function ProfilesSideRail({
  profiles,
  selectedName,
  searchQuery,
  runtimeFilter,
  searchInputRef,
  onSearchChange,
  onRuntimeFilterChange,
  onSelectProfile,
}: ProfilesSideRailProps) {
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
        p.manifest.default_target.toLowerCase().includes(query) ||
        p.manifest.link_policy.toLowerCase().includes(query)
      );
    });
  }, [profiles, runtimeFilter, searchQuery]);

  return (
    <SideNav
      aria-label="Sandbox profiles"
      resizable={{ defaultWidth: 300, minWidth: 240, maxWidth: 420 }}
      header={
        <SideNavHeading
          heading="Profiles"
          subheading={`${profiles.length} provisioned`}
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
      <SideNavSection title="Provisioned Profiles" isHeaderHidden>
        {filteredProfiles.length === 0 ? (
          <VStack padding={3}>
            <Text type="supporting" color="secondary">
              {profiles.length === 0
                ? "No profiles provisioned yet."
                : "No profiles match this filter."}
            </Text>
          </VStack>
        ) : (
          <List density="balanced" hasDividers>
            {filteredProfiles.map((profile) => {
              const combined = computeCombinedState(profile.runtime);
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
                  description={`${profile.manifest.name} · ${profile.manifest.default_target.toUpperCase()} · ${formatBytes(profile.disk_bytes)}`}
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

export interface ProfilesDetailPaneProps {
  profiles: ProfileSummary[];
  detail: ProfileDetail | null;
  targets: { hub: TargetInfo; ide: TargetInfo } | null;
  detailLoading: boolean;
  actionBusy: string | null;
  confirmDeleteOpen: boolean;
  onConfirmDeleteOpenChange: (open: boolean) => void;
  onOpenCreate: () => void;
  onOpenClone: () => void;
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
  detail,
  targets,
  detailLoading,
  actionBusy,
  confirmDeleteOpen,
  onConfirmDeleteOpenChange,
  onOpenCreate,
  onOpenClone,
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

  if (profiles.length === 0) {
    return (
      <Layout
        padding={6}
        height="fill"
        content={
          <LayoutContent>
            <EmptyState
              headingLevel={1}
              title="No profiles provisioned"
              description="Create a sandbox profile with separate OAuth tokens and locked HOME paths."
              actions={
                <Button
                  variant="primary"
                  label="New Profile"
                  onClick={onOpenCreate}
                />
              }
            />
          </LayoutContent>
        }
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
    {
      id: "repair",
      label: "Repair Locks",
      icon: <Icon icon="wrench" size="sm" />,
      isDisabled: actionBusy !== null,
      onClick: () => void onRepair(detail.manifest.name),
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
                      {detail.runtime.hub.pids.length > 0
                        ? `PID ${detail.runtime.hub.pids.join(", ")}`
                        : pluralize(detail.runtime.hub.lock_files.length, "lock")}
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
                      {detail.runtime.ide.pids.length > 0
                        ? `PID ${detail.runtime.ide.pids.join(", ")}`
                        : pluralize(detail.runtime.ide.lock_files.length, "lock")}
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
                              label: "Dev (toolchain caches)",
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
