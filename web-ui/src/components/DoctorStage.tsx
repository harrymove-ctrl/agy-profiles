import { Badge, type BadgeVariant } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Grid } from "@astryxdesign/core/Grid";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent } from "@astryxdesign/core/Layout";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { StatusDot, type StatusDotVariant } from "@astryxdesign/core/StatusDot";
import { Table, pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import type { DoctorCheck, DoctorResponse, TargetInfo } from "../types";

function checkBadgeVariant(status: string): BadgeVariant {
  if (status === "pass") {
    return "success";
  }
  if (status === "warn") {
    return "warning";
  }
  return "error";
}

function checkDotVariant(status: string): StatusDotVariant {
  if (status === "pass") {
    return "success";
  }
  if (status === "warn") {
    return "warning";
  }
  return "error";
}

const columns: TableColumn<DoctorCheck>[] = [
  {
    key: "status",
    header: "Status",
    width: pixel(120),
    renderCell: (item) => (
      <HStack gap={1.5} vAlign="center">
        <StatusDot
          variant={checkDotVariant(item.status)}
          label={item.status}
        />
        <Badge variant={checkBadgeVariant(item.status)} label={item.status} />
      </HStack>
    ),
  },
  {
    key: "id",
    header: "Check",
    width: proportional(1, { minWidth: 160 }),
    renderCell: (item) => <Code>{item.id}</Code>,
  },
  {
    key: "detail",
    header: "Detail",
    width: proportional(2.4, { minWidth: 240 }),
    renderCell: (item) => <Text>{item.detail}</Text>,
  },
];

function TargetBundleCard({ target }: { target: TargetInfo }) {
  return (
    <Card padding={4}>
      <VStack gap={3}>
        <HStack hAlign="between" vAlign="center">
          <Heading level={2}>{target.display_name}</Heading>
          <Badge
            variant={target.installed ? "success" : "warning"}
            label={target.installed ? `v${target.version}` : "Not Detected"}
          />
        </HStack>
        <MetadataList columns={1} label={{ position: "start", width: 120 }}>
          <MetadataListItem label="Bundle ID">
            <Code>{target.bundle_id || "none"}</Code>
          </MetadataListItem>
          <MetadataListItem label="App Bundle">
            <Code>{target.app_path ?? "missing"}</Code>
          </MetadataListItem>
          <MetadataListItem label="Executable">
            <Code>{target.binary_path ?? "missing"}</Code>
          </MetadataListItem>
        </MetadataList>
      </VStack>
    </Card>
  );
}

export interface DoctorStageProps {
  doctor: DoctorResponse | null;
  loading: boolean;
  onRefresh: () => void;
}

export function DoctorStage({ doctor, loading, onRefresh }: DoctorStageProps) {
  if (!doctor) {
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
                  ? "Running host diagnostics..."
                  : "Host diagnostics not yet loaded"
              }
              description="Inspect macOS Antigravity Hub and IDE bundles, Python runtime version, osacompile availability, and sandbox root permissions."
              actions={
                <Button
                  variant="primary"
                  label="Run Diagnostics"
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

  return (
    <Layout
      padding={6}
      height="fill"
      content={
        <LayoutContent>
          <VStack gap={4}>
            <Card padding={5}>
              <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
                <VStack gap={1}>
                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Heading level={1}>Host &amp; Sandbox Diagnostics</Heading>
                    <Code>{doctor.evidence.evidence_id}</Code>
                  </HStack>
                  <Text type="supporting" color="secondary">
                    {doctor.evidence.summary} · Observed {doctor.evidence.observed_at}
                  </Text>
                </VStack>
                <Button
                  variant="secondary"
                  label="Refresh Diagnostics"
                  isLoading={loading}
                  onClick={onRefresh}
                />
              </HStack>
            </Card>

            <Grid columns={{ minWidth: 320, max: 2 }} gap={4}>
              <TargetBundleCard target={doctor.targets.hub} />
              <TargetBundleCard target={doctor.targets.ide} />
            </Grid>

            <Card padding={0}>
              <Table
                data={doctor.checks}
                columns={columns}
                idKey="id"
                density="balanced"
                dividers="rows"
                hasHover
              />
            </Card>
          </VStack>
        </LayoutContent>
      }
    />
  );
}
