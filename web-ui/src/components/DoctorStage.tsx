import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Grid } from "@astryxdesign/core/Grid";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent, LayoutHeader } from "@astryxdesign/core/Layout";
import { MetadataList, MetadataListItem } from "@astryxdesign/core/MetadataList";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Table, pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
import { VStack } from "@astryxdesign/core/VStack";
import type { DoctorCheck, DoctorResponse, TargetInfo } from "../types";

const columns: TableColumn<DoctorCheck>[] = [
  {
    key: "status",
    header: "Status",
    width: pixel(120),
    renderCell: (item) => {
      if (item.status === "pass") {
        return (
          <HStack gap={1.5} vAlign="center">
            <StatusDot variant="success" label="Passed" />
            <Text weight="medium">Passed</Text>
          </HStack>
        );
      }
      if (item.status === "warn") {
        return (
          <HStack gap={1.5} vAlign="center">
            <StatusDot variant="warning" label="Warning" />
            <Badge variant="warning" label="Warning" />
          </HStack>
        );
      }
      return (
        <HStack gap={1.5} vAlign="center">
          <StatusDot variant="error" label="Failed" />
          <Badge variant="error" label="Failed" />
        </HStack>
      );
    },
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

function TargetBundleSection({ target }: { target: TargetInfo }) {
  return (
    <Card padding={4}>
      <VStack gap={3}>
        <HStack hAlign="between" vAlign="center">
          <Heading level={2}>{target.display_name}</Heading>
          {target.installed ? (
            <Text type="supporting" color="secondary" hasTabularNumbers>
              v{target.version}
            </Text>
          ) : (
            <Badge variant="warning" label="Missing" />
          )}
        </HStack>
        <MetadataList columns={1} label={{ position: "start", width: 120 }}>
          <MetadataListItem label="Bundle ID">
            <Code>{target.bundle_id || "--"}</Code>
          </MetadataListItem>
          <MetadataListItem label="App Bundle">
            <Code>{target.app_path ?? "--"}</Code>
          </MetadataListItem>
          <MetadataListItem label="Executable">
            <Code>{target.binary_path ?? "--"}</Code>
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
              title={loading ? "Running host diagnostics..." : "Host diagnostics"}
              description="Check Antigravity app bundles, Python runtime, launcher tools, and root permissions."
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
      header={
        <LayoutHeader hasDivider>
          <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
            <VStack gap={1}>
              <HStack gap={2} vAlign="center" wrap="wrap">
                <Heading level={1}>Host Diagnostics</Heading>
                <Code>{doctor.evidence.evidence_id}</Code>
              </HStack>
              <Text type="supporting" color="secondary">
                {doctor.evidence.summary} ·{" "}
                <Timestamp
                  value={doctor.evidence.observed_at}
                  format="date_time"
                  timezoneID="UTC"
                  isTimezoneShown
                />
              </Text>
            </VStack>
            <Button
              size="sm"
              variant="secondary"
              label="Run Diagnostics"
              tooltip="Run diagnostics (R)"
              isLoading={loading}
              onClick={onRefresh}
            />
          </HStack>
        </LayoutHeader>
      }
      content={
        <LayoutContent>
          <VStack gap={4}>
            <Grid columns={{ minWidth: 320, max: 2 }} gap={4}>
              <TargetBundleSection target={doctor.targets.hub} />
              <TargetBundleSection target={doctor.targets.ide} />
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
