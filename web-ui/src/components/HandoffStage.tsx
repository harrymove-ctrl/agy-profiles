import { useMemo } from "react";
import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { CodeBlock } from "@astryxdesign/core/CodeBlock";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent, LayoutHeader } from "@astryxdesign/core/Layout";
import { Selector } from "@astryxdesign/core/Selector";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Table, pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { Token } from "@astryxdesign/core/Token";
import { VStack } from "@astryxdesign/core/VStack";
import { isEmbeddedSidecar, pluralize, startSidecarConversation } from "../api";
import type {
  AutomationsMode,
  HandoffConversation,
  HandoffResponse,
  HostAccountInfo,
  HostRuntimeInfo,
  ProfileSummary,
} from "../types";

export interface HandoffStageProps {
  handoff: HandoffResponse | null;
  hostAccount?: HostAccountInfo | null;
  hostRuntime?: HostRuntimeInfo | null;
  profiles: ProfileSummary[];
  selectedSource: string;
  selectedProfile: string | null;
  loading: boolean;
  syncBusy: string | null;
  errorMessage?: string | null;
  onRefresh: () => void;
  onSelectSource: (source: string) => void;
  onSelectProfile: (name: string) => void;
  onSyncProfile: (
    name: string,
    restart: boolean,
    automationsMode?: AutomationsMode
  ) => Promise<void>;
  onSwitchProfile: (name: string) => Promise<void>;
  onReturnHost: (fromProfile: string) => Promise<void>;
  onOpenCreate: () => void;
}

const columns: TableColumn<HandoffConversation>[] = [
  {
    key: "project",
    header: "Project",
    width: proportional(1.0, { minWidth: 150 }),
    renderCell: (item) => (
      <VStack gap={0.5}>
        <Text weight="medium">{item.project}</Text>
        <Text type="supporting" color="secondary">
          {item.status}
        </Text>
      </VStack>
    ),
  },
  {
    key: "title",
    header: "Conversation",
    width: proportional(1.5, { minWidth: 210 }),
    renderCell: (item) => (
      <VStack gap={0.5}>
        <Text weight="medium">{item.title}</Text>
        <Code>{item.conversation_id}</Code>
      </VStack>
    ),
  },
  {
    key: "summary",
    header: "Latest Request and Context",
    width: proportional(2.1, { minWidth: 260 }),
    renderCell: (item) => (
      <VStack gap={0.5}>
        <Text type="supporting">
          {item.last_user_request || "No recorded user request."}
        </Text>
        {item.last_agent_summary ? (
          <Text type="supporting" color="secondary">
            {item.last_agent_summary}
          </Text>
        ) : null}
      </VStack>
    ),
  },
  {
    key: "updated_at",
    header: "Updated",
    width: pixel(160),
    renderCell: (item) => (
      <Text type="supporting" color="secondary" hasTabularNumbers>
        {item.updated_at || "--"}
      </Text>
    ),
  },
];

export function HandoffStage({
  handoff,
  hostAccount = null,
  hostRuntime = null,
  profiles,
  selectedSource,
  selectedProfile,
  loading,
  syncBusy,
  errorMessage,
  onRefresh,
  onSelectSource,
  onSelectProfile,
  onSyncProfile,
  onSwitchProfile,
  onReturnHost,
  onOpenCreate,
}: HandoffStageProps) {
  const hostRunning =
    hostRuntime?.hub.state === "running" || hostRuntime?.ide.state === "running";

  const effectiveTarget = useMemo(() => {
    if (
      selectedProfile &&
      profiles.some((p) => p.manifest.name === selectedProfile)
    ) {
      return selectedProfile;
    }
    const nonSource = profiles.find((p) => p.manifest.name !== selectedSource);
    return (nonSource ?? profiles[0])?.manifest.name ?? null;
  }, [profiles, selectedProfile, selectedSource]);

  const sourceOptions = useMemo(() => {
    const stateLabel = hostRuntime
      ? hostRunning
        ? "Running"
        : "Stopped"
      : "Primary";
    const opts = [
      {
        value: "host",
        label: hostAccount?.email
          ? `Host: ${hostAccount.email} (${stateLabel})`
          : `Host (${stateLabel})`,
      },
    ];
    for (const p of profiles) {
      const email = p.account?.email;
      const label =
        email &&
        !p.manifest.label.toLowerCase().includes(email.toLowerCase())
          ? `${p.manifest.label} (${email})`
          : p.manifest.label;
      opts.push({ value: p.manifest.name, label });
    }
    return opts;
  }, [hostAccount, hostRunning, hostRuntime, profiles]);

  const profileOptions = useMemo(
    () =>
      profiles.map((p) => {
        const email = p.account?.email;
        const label =
          email &&
          !p.manifest.label.toLowerCase().includes(email.toLowerCase())
            ? `${p.manifest.label} (${email})`
            : p.manifest.label;
        return {
          value: p.manifest.name,
          label,
        };
      }),
    [profiles]
  );

  if (!handoff) {
    return (
      <Layout
        padding={6}
        height="fill"
        content={
          <LayoutContent>
            <EmptyState
              headingLevel={1}
              title={
                loading
                  ? "Reading conversation handoff..."
                  : "Conversation handoff unavailable"
              }
              description={
                errorMessage ??
                "Reads Antigravity conversations strictly read-only so another account picks up active work."
              }
              actions={
                <Button
                  variant="primary"
                  label="Read Handoff Digest"
                  isLoading={loading}
                  onClick={onRefresh}
                />
              }
            />
          </LayoutContent>
        }
      />
    );
  }

  const activeSourceEmail = handoff.source_account ?? handoff.host_account;
  const sourceLabel =
    selectedSource === "host"
      ? activeSourceEmail
        ? `Host: ${activeSourceEmail}`
        : "Host unsigned"
      : `${selectedSource}${activeSourceEmail ? `: ${activeSourceEmail}` : ""}`;
  const canStartSidecarChat = isEmbeddedSidecar();

  return (
    <Layout
      padding={6}
      height="fill"
      header={
        <LayoutHeader hasDivider>
          <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
            <VStack gap={1}>
              <HStack gap={2} vAlign="center" wrap="wrap">
                <Heading level={1}>Cross-Account Handoff</Heading>
                <StatusDot
                  variant={handoff.available ? "success" : "warning"}
                  label={handoff.available ? "Read-only DB" : "Unavailable"}
                />
                <Token size="sm" color="gray" label={sourceLabel} />
              </HStack>
              <Text type="supporting" color="secondary" hasTabularNumbers>
                {pluralize(handoff.count, "recent thread")} · Read-only SQLite ·{" "}
                <Timestamp
                  value={handoff.generated_at}
                  format="date_time"
                  timezoneID="UTC"
                  isTimezoneShown
                />
              </Text>
            </VStack>
            <HStack gap={2} vAlign="center" wrap="wrap">
              <Selector
                label="Handoff source"
                isLabelHidden
                size="sm"
                variant="secondary"
                value={selectedSource}
                onChange={(next) => onSelectSource(next)}
                options={sourceOptions}
              />
              {selectedSource !== "host" ? (
                <Button
                  size="sm"
                  variant="primary"
                  label="Return to Host"
                  tooltip="Write backup handoff into Main Antigravity, pause backup Automations, and copy resume prompt"
                  isDisabled={syncBusy !== null}
                  isLoading={syncBusy === "return-host"}
                  onClick={() => void onReturnHost(selectedSource)}
                />
              ) : null}
              {profiles.length > 0 ? (
                <>
                  {selectedSource === "host" || profiles.length > 1 ? (
                    <>
                      <Selector
                        label="Target profile"
                        isLabelHidden
                        size="sm"
                        variant="secondary"
                        value={effectiveTarget ?? undefined}
                        onChange={(next) => onSelectProfile(next)}
                        options={profileOptions}
                      />
                      <Button
                        size="sm"
                        variant="secondary"
                        label="Sync to Profile"
                        tooltip="Sync clickable sessions, HANDOFF_CONTEXT.md, sanitized setup, and paused Automations"
                        isDisabled={!effectiveTarget || syncBusy !== null}
                        isLoading={syncBusy === "sync"}
                        onClick={() =>
                          effectiveTarget &&
                          void onSyncProfile(effectiveTarget, false, "paused")
                        }
                      />
                      <Button
                        size="sm"
                        variant={selectedSource === "host" ? "primary" : "secondary"}
                        label="Take Over Quota"
                        tooltip="Sync clickable sessions, enable Automations, and launch target profile"
                        isDisabled={!effectiveTarget || syncBusy !== null}
                        isLoading={syncBusy === "switch"}
                        onClick={() =>
                          effectiveTarget && void onSwitchProfile(effectiveTarget)
                        }
                      />
                    </>
                  ) : null}
                </>
              ) : (
                <Button
                  size="sm"
                  variant="primary"
                  label="Create Profile"
                  onClick={onOpenCreate}
                />
              )}
              <Button
                size="sm"
                variant="secondary"
                label="Refresh"
                tooltip="Reload conversations (R)"
                isLoading={loading}
                onClick={onRefresh}
              />
            </HStack>
          </HStack>
        </LayoutHeader>
      }
      content={
        <LayoutContent>
          <VStack gap={5}>
            {errorMessage ? (
              <Card padding={3}>
                <HStack gap={2} vAlign="center" wrap="wrap">
                  <Badge variant="error" label="Sync notice" />
                  <Text type="supporting">{errorMessage}</Text>
                </HStack>
              </Card>
            ) : null}
            <Card padding={4}>
              <VStack gap={3}>
                <HStack hAlign="between" vAlign="center" gap={2} wrap="wrap">
                  <VStack gap={0.5}>
                    <Heading level={2}>Cross-Account Resume Prompt</Heading>
                    <Text type="supporting" color="secondary">
                      Written to HANDOFF_CONTEXT.md inside each synced sandbox and referenced in GEMINI.md.
                    </Text>
                  </VStack>
                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Code>{handoff.db_path}</Code>
                    {canStartSidecarChat &&
                    handoff.available &&
                    handoff.resume_prompt ? (
                      <Button
                        size="sm"
                        variant="secondary"
                        label="Resume in New Chat"
                        onClick={() =>
                          void startSidecarConversation(
                            handoff.resume_prompt,
                            "Handoff Resume"
                          )
                        }
                      />
                    ) : null}
                  </HStack>
                </HStack>
                {handoff.available ? (
                  <CodeBlock
                    code={handoff.resume_prompt || "No recent threads recorded."}
                    language="plaintext"
                    title="HANDOFF_CONTEXT.md digest"
                    container="section"
                    width="100%"
                    isWrapped
                    hasCopyButton
                  />
                ) : (
                  <Text type="supporting" color="secondary">
                    {handoff.reason ?? "Conversation database is unavailable."}
                  </Text>
                )}
              </VStack>
            </Card>
            {handoff.conversations.length > 0 ? (
              <Card padding={0}>
                <Table
                  data={handoff.conversations}
                  columns={columns}
                  idKey="conversation_id"
                  density="balanced"
                  dividers="rows"
                  hasHover
                />
              </Card>
            ) : null}
          </VStack>
        </LayoutContent>
      }
    />
  );
}
