import { useEffect, useMemo, useState, type RefObject } from "react";
import { Badge, type BadgeVariant } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { Code } from "@astryxdesign/core/Code";
import { Divider } from "@astryxdesign/core/Divider";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { FormLayout } from "@astryxdesign/core/FormLayout";
import { Grid } from "@astryxdesign/core/Grid";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { Layout, LayoutContent } from "@astryxdesign/core/Layout";
import { List, ListItem } from "@astryxdesign/core/List";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
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
import { StatusDot, type StatusDotVariant } from "@astryxdesign/core/StatusDot";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import {
  ACCENT_PRESETS,
  computeCombinedState,
  formatBytes,
  profileInitials,
  resolveAccentKey,
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

function runtimeBadgeVariant(state: RuntimeStateType): BadgeVariant {
  if (state === "running") {
    return "success";
  }
  if (state === "stale-lock") {
    return "warning";
  }
  return "neutral";
}

function runtimeDotVariant(state: RuntimeStateType): StatusDotVariant {
  if (state === "running") {
    return "success";
  }
  if (state === "stale-lock") {
    return "warning";
  }
  return "neutral";
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
          heading="Sandboxes"
          subheading={`${profiles.length} isolated ${profiles.length === 1 ? "profile" : "profiles"}`}
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
      <SideNavSection
        title="Provisioned Profiles"
        isHeaderHidden
      >
        {filteredProfiles.length === 0 ? (
          <VStack padding={3}>
            <Text type="supporting" color="secondary">
              {profiles.length === 0
                ? "No sandbox profiles have been provisioned yet."
                : "No profiles match the active filter."}
            </Text>
          </VStack>
        ) : (
          <List density="balanced" hasDividers>
            {filteredProfiles.map((profile) => {
              const combined = computeCombinedState(profile.runtime);
              const accentKey = resolveAccentKey(profile.manifest.accent);
              return (
                <ListItem
                  key={profile.manifest.name}
                  isSelected={selectedName === profile.manifest.name}
                  onClick={() => onSelectProfile(profile.manifest.name)}
                  startContent={
                    <span
                      className="agyp-profile-dot"
                      data-accent={accentKey}
                      aria-hidden="true"
                    />
                  }
                  label={profile.manifest.label}
                  description={`${profile.manifest.name} · ${profile.manifest.default_target.toUpperCase()} · ${formatBytes(profile.disk_bytes)}`}
                  endContent={
                    <Badge
                      variant={runtimeBadgeVariant(combined)}
                      label={combined === "stale-lock" ? "stale" : combined}
                    />
                  }
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
              title="No sandbox profiles provisioned"
              description="Create an isolated Antigravity profile with dedicated OAuth credentials, scoped environment locks, and explicit symlink boundaries."
              actions={
                <Button
                  variant="primary"
                  label="Create First Profile"
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
              title={
                detailLoading
                  ? "Loading sandbox inspection..."
                  : "Select a sandbox profile"
              }
              description="Pick a profile from the side rail to inspect filesystem permissions, lock health, and launch targets."
            />
          </LayoutContent>
        }
      />
    );
  }

  const combinedState = computeCombinedState(detail.runtime);
  const accentKey = resolveAccentKey(detail.manifest.accent);
  const hasDefaultLauncher = detail.launchers[detail.manifest.default_target];
  const anyRunning = combinedState === "running";
  const hubInstalled = targets?.hub.installed ?? true;
  const ideInstalled = targets?.ide.installed ?? true;

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
    <Layout
      padding={6}
      height="fill"
      content={
        <LayoutContent>
          <VStack gap={5}>
            <Card padding={5}>
              <VStack gap={4}>
                <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
                  <HStack gap={3} vAlign="center" wrap="wrap">
                    <div
                      className="agyp-profile-monogram"
                      data-accent={accentKey}
                      aria-hidden="true"
                    >
                      {profileInitials(detail.manifest.label, detail.manifest.name)}
                    </div>
                    <VStack gap={1}>
                      <HStack gap={2} vAlign="center" wrap="wrap">
                        <Heading level={1}>{detail.manifest.label}</Heading>
                        <Code>{detail.manifest.name}</Code>
                        <Badge
                          variant={runtimeBadgeVariant(combinedState)}
                          label={combinedState}
                        />
                        <Badge
                          variant="neutral"
                          label={detail.manifest.auth_mode}
                        />
                        <Badge
                          variant="info"
                          label={`links:${detail.manifest.link_policy}`}
                        />
                      </HStack>
                      <Text type="supporting" color="secondary">
                        Created {detail.manifest.created_at}
                        {detail.manifest.last_launched_at
                          ? ` · Last launched ${detail.manifest.last_launched_at}`
                          : " · Never launched"}
                      </Text>
                    </VStack>
                  </HStack>

                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Button
                      size="sm"
                      variant={
                        detail.manifest.default_target === "hub"
                          ? "primary"
                          : "secondary"
                      }
                      label="Launch Hub"
                      isDisabled={!hubInstalled || actionBusy !== null}
                      isLoading={actionBusy === "launch-hub"}
                      onClick={() => onLaunch(detail.manifest.name, "hub")}
                    />
                    <Button
                      size="sm"
                      variant={
                        detail.manifest.default_target === "ide"
                          ? "primary"
                          : "secondary"
                      }
                      label="Launch IDE"
                      isDisabled={!ideInstalled || actionBusy !== null}
                      isLoading={actionBusy === "launch-ide"}
                      onClick={() => onLaunch(detail.manifest.name, "ide")}
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      icon={<Icon icon="stop" size="sm" />}
                      label="Stop"
                      isDisabled={!anyRunning || actionBusy !== null}
                      isLoading={actionBusy === "stop"}
                      onClick={() => onStop(detail.manifest.name)}
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      icon={<Icon icon="wrench" size="sm" />}
                      label="Repair"
                      isDisabled={actionBusy !== null}
                      isLoading={actionBusy === "repair"}
                      onClick={() => onRepair(detail.manifest.name)}
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      label="Clone"
                      isDisabled={anyRunning || actionBusy !== null}
                      onClick={onOpenClone}
                    />
                    <Button
                      size="sm"
                      variant="secondary"
                      label={
                        hasDefaultLauncher ? "Remove Launcher" : "Build Launcher"
                      }
                      isDisabled={actionBusy !== null}
                      isLoading={actionBusy === "launcher"}
                      onClick={() =>
                        onToggleLauncher(
                          detail.manifest.name,
                          detail.manifest.default_target,
                          hasDefaultLauncher
                        )
                      }
                    />
                    {!confirmDeleteOpen ? (
                      <Button
                        size="sm"
                        variant="destructive"
                        label="Delete"
                        isDisabled={actionBusy !== null}
                        onClick={() => onConfirmDeleteOpenChange(true)}
                      />
                    ) : null}
                  </HStack>
                </HStack>

                {confirmDeleteOpen ? (
                  <Card variant="muted" padding={3}>
                    <HStack hAlign="between" vAlign="center" gap={3} wrap="wrap">
                      <VStack gap={1}>
                        <Text weight="semibold">
                          Delete sandbox profile &ldquo;{detail.manifest.name}&rdquo;?
                        </Text>
                        <Text type="supporting" color="secondary">
                          This permanently removes profile manifests, sandbox home config, and stored session tokens.
                        </Text>
                      </VStack>
                      <HStack gap={3} vAlign="center" wrap="wrap">
                        <CheckboxInput
                          label="Force stop running processes"
                          value={forceStopDelete}
                          onChange={(checked) => setForceStopDelete(checked)}
                        />
                        <Button
                          size="sm"
                          variant="ghost"
                          label="Cancel"
                          isDisabled={actionBusy !== null}
                          onClick={() => onConfirmDeleteOpenChange(false)}
                        />
                        <Button
                          size="sm"
                          variant="destructive"
                          label="Confirm Delete"
                          isLoading={actionBusy === "delete"}
                          onClick={() =>
                            onDeleteProfile(detail.manifest.name, forceStopDelete)
                          }
                        />
                      </HStack>
                    </HStack>
                  </Card>
                ) : null}
              </VStack>
            </Card>

            <Grid columns={{ minWidth: 190, max: 4 }} gap={3}>
              <Card padding={4}>
                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Hub Runtime
                  </Text>
                  <HStack gap={2} vAlign="center">
                    <StatusDot
                      variant={runtimeDotVariant(detail.runtime.hub.state)}
                      label={detail.runtime.hub.state}
                    />
                    <Heading level={3}>{detail.runtime.hub.state}</Heading>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {detail.runtime.hub.pids.length > 0
                      ? `PIDs: ${detail.runtime.hub.pids.join(", ")}`
                      : `No active PIDs · ${detail.runtime.hub.lock_files.length} lock(s)`}
                  </Text>
                </VStack>
              </Card>

              <Card padding={4}>
                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    IDE Runtime
                  </Text>
                  <HStack gap={2} vAlign="center">
                    <StatusDot
                      variant={runtimeDotVariant(detail.runtime.ide.state)}
                      label={detail.runtime.ide.state}
                    />
                    <Heading level={3}>{detail.runtime.ide.state}</Heading>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {detail.runtime.ide.pids.length > 0
                      ? `PIDs: ${detail.runtime.ide.pids.join(", ")}`
                      : `No active PIDs · ${detail.runtime.ide.lock_files.length} lock(s)`}
                  </Text>
                </VStack>
              </Card>

              <Card padding={4}>
                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Sandbox Footprint
                  </Text>
                  <Heading level={3}>
                    {formatBytes(detail.disk_bytes)}
                  </Heading>
                  <Text type="supporting" color="secondary">
                    Updated {detail.manifest.updated_at}
                  </Text>
                </VStack>
              </Card>

              <Card padding={4}>
                <VStack gap={1}>
                  <Text type="label" color="secondary">
                    Boundary Posture
                  </Text>
                  <HStack gap={2} vAlign="center">
                    <StatusDot
                      variant={
                        detail.isolation.zshenv_home_locked &&
                        detail.isolation.forbidden_symlinks_present.length === 0
                          ? "success"
                          : "error"
                      }
                      label={
                        detail.isolation.zshenv_home_locked
                          ? "HOME Locked"
                          : "Unlocked"
                      }
                    />
                    <Heading level={3}>
                      {detail.isolation.zshenv_home_locked
                        ? "HOME Locked"
                        : "Unlocked"}
                    </Heading>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    {detail.isolation.forbidden_symlinks_present.length} forbidden ·{" "}
                    {detail.isolation.active_symlinks.length} managed link(s)
                  </Text>
                </VStack>
              </Card>
            </Grid>

            <Grid columns={{ minWidth: 340, max: 2 }} gap={4}>
              <Card padding={5}>
                <VStack gap={4}>
                  <Heading level={2}>Isolation &amp; Policy</Heading>
                  <form onSubmit={handleSave}>
                    <FormLayout direction="vertical">
                      <TextInput
                        label="Display Label"
                        value={editLabel}
                        onChange={setEditLabel}
                        isRequired
                      />
                      <VStack gap={1.5}>
                        <HStack hAlign="between" vAlign="center">
                          <Text type="label">Profile Accent</Text>
                          <Code>{editAccent}</Code>
                        </HStack>
                        <div
                          className="agyp-swatch-row"
                          role="radiogroup"
                          aria-label="Profile accent color"
                        >
                          {ACCENT_PRESETS.map((preset) => {
                            const selected =
                              editAccent.toUpperCase() === preset.hex.toUpperCase();
                            return (
                              <button
                                key={preset.key}
                                type="button"
                                role="radio"
                                aria-checked={selected}
                                aria-label={preset.label}
                                title={`${preset.label} (${preset.hex})`}
                                className="agyp-swatch-button"
                                data-accent={preset.key}
                                onClick={() => setEditAccent(preset.hex)}
                              />
                            );
                          })}
                        </div>
                      </VStack>
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
                        label="Symlink Inheritance Policy"
                        value={editLinkPolicy}
                        onChange={(val) => setEditLinkPolicy(val as LinkPolicy)}
                        options={[
                          {
                            value: "none",
                            label: "none (Strict zero host links)",
                          },
                          {
                            value: "minimal",
                            label: "minimal (Non-secret fonts and caches)",
                          },
                          {
                            value: "dev",
                            label: "dev (Include developer toolchain caches)",
                          },
                        ]}
                      />
                      <Selector
                        label="Auth Storage Mode"
                        value={editAuthMode}
                        onChange={(val) => setEditAuthMode(val as AuthMode)}
                        options={[
                          {
                            value: "isolated-file",
                            label: "isolated-file (Per-sandbox token isolation)",
                          },
                          {
                            value: "system-keychain",
                            label: "system-keychain (Shared macOS login keychain)",
                          },
                        ]}
                      />
                      <Switch
                        label="Keep background helper processes alive on close"
                        value={editKeepBg}
                        onChange={(checked) => setEditKeepBg(checked)}
                      />
                      <HStack hAlign="end">
                        <Button
                          type="submit"
                          variant="primary"
                          label="Save Policy Changes"
                          isLoading={actionBusy === "save"}
                          isDisabled={actionBusy !== null}
                        />
                      </HStack>
                    </FormLayout>
                  </form>

                  <Divider />

                  <VStack gap={2}>
                    <Heading level={3}>On-Disk Permissions Audit</Heading>
                    <MetadataList
                      columns={1}
                      label={{ position: "start", width: 155 }}
                    >
                      <MetadataListItem label="profile_dir">
                        <Code>{detail.isolation.permissions.profile_dir ?? "missing"}</Code>
                      </MetadataListItem>
                      <MetadataListItem label="data_dir">
                        <Code>{detail.isolation.permissions.data_dir ?? "missing"}</Code>
                      </MetadataListItem>
                      <MetadataListItem label="sandbox_home">
                        <Code>{detail.isolation.permissions.sandbox_home ?? "missing"}</Code>
                      </MetadataListItem>
                      <MetadataListItem label=".zshenv">
                        <Code>{detail.isolation.permissions.zshenv_file ?? "missing"}</Code>
                      </MetadataListItem>
                      <MetadataListItem label="oauth_token_file">
                        <Code>
                          {detail.isolation.permissions.oauth_token_file ?? "absent"}
                        </Code>
                      </MetadataListItem>
                      <MetadataListItem label="mcp_config_file">
                        <Code>
                          {detail.isolation.permissions.mcp_config_file ?? "absent"}
                        </Code>
                      </MetadataListItem>
                      <MetadataListItem label="Active Symlinks">
                        <Text hasTabularNumbers>
                          {detail.isolation.active_symlinks.length}
                        </Text>
                      </MetadataListItem>
                    </MetadataList>
                  </VStack>
                </VStack>
              </Card>

              <Card padding={5}>
                <VStack gap={4}>
                  <Heading level={2}>Evidence &amp; Security Ledger</Heading>
                  <Text>{detail.evidence.summary}</Text>
                  <MetadataList
                    columns={1}
                    label={{ position: "start", width: 140 }}
                  >
                    <MetadataListItem label="Evidence ID">
                      <Code>{detail.evidence.evidence_id}</Code>
                    </MetadataListItem>
                    <MetadataListItem label="Authority">
                      <Badge
                        variant="info"
                        label={`${detail.evidence.authority} (${detail.evidence.confidence})`}
                      />
                    </MetadataListItem>
                    <MetadataListItem label="Observed">
                      <Text hasTabularNumbers>{detail.evidence.observed_at}</Text>
                    </MetadataListItem>
                    <MetadataListItem label="Profile Root">
                      <Code>{detail.paths.profile_dir}</Code>
                    </MetadataListItem>
                    <MetadataListItem label="Hub Data Dir">
                      <Code>{detail.paths.data_dir}</Code>
                    </MetadataListItem>
                    <MetadataListItem label="IDE Data Dir">
                      <Code>{detail.paths.ide_data_dir}</Code>
                    </MetadataListItem>
                    <MetadataListItem label="Sandbox HOME">
                      <Code>{detail.paths.sandbox_home}</Code>
                    </MetadataListItem>
                  </MetadataList>

                  <Divider />

                  <VStack gap={2}>
                    <Heading level={3}>Explicit Inspection Boundaries</Heading>
                    <List density="compact" hasDividers>
                      {detail.evidence.limitations.map((limitation, idx) => (
                        <ListItem
                          key={idx}
                          startContent={<Icon icon="info" size="sm" color="secondary" />}
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
  );
}
