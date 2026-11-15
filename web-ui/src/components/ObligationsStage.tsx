import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent } from "@astryxdesign/core/Layout";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Table, pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { VStack } from "@astryxdesign/core/VStack";
import type { ObligationItem, ObligationsResponse } from "../types";

export interface ObligationsStageProps {
  report: ObligationsResponse | null;
  loading: boolean;
  onRefresh: () => void;
}

const columns: TableColumn<ObligationItem>[] = [
  {
    key: "status",
    header: "Status",
    width: pixel(120),
    renderCell: (item) => {
      const closed = item.status === "closed";
      return (
        <HStack gap={1.5} vAlign="center">
          <StatusDot
            variant={closed ? "success" : "error"}
            label={item.status}
          />
          <Badge
            variant={closed ? "success" : "error"}
            label={item.status}
          />
        </HStack>
      );
    },
  },
  {
    key: "obligation_id",
    header: "Obligation",
    width: proportional(1.2, { minWidth: 180 }),
    renderCell: (item) => <Code>{item.obligation_id}</Code>,
  },
  {
    key: "title",
    header: "Invariant",
    width: proportional(1.6, { minWidth: 200 }),
    renderCell: (item) => <Text weight="medium">{item.title}</Text>,
  },
  {
    key: "owner_module",
    header: "Owner Digest",
    width: proportional(1.1, { minWidth: 160 }),
    renderCell: (item) => (
      <VStack gap={0.5}>
        <Code>{item.owner_module}</Code>
        <Text type="supporting" color="secondary" hasTabularNumbers>
          sha256:{item.module_sha256.slice(0, 12)}
        </Text>
      </VStack>
    ),
  },
  {
    key: "cases_checked",
    header: "Cases",
    width: proportional(1, { minWidth: 130 }),
    renderCell: (item) => (
      <Text type="supporting" color="secondary">
        {item.cases_checked.join(", ")}
      </Text>
    ),
  },
  {
    key: "detail",
    header: "Observed Proof",
    width: proportional(1.8, { minWidth: 220 }),
    renderCell: (item) => (
      <Text type="supporting" color="secondary">
        {item.detail}
      </Text>
    ),
  },
];

export function ObligationsStage({
  report,
  loading,
  onRefresh,
}: ObligationsStageProps) {
  if (!report) {
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
                  ? "Verifying security obligations..."
                  : "Security obligation ledger unavailable"
              }
              description="Run live self-checks against slug validation, path containment, symlink boundaries, MCP secret scrubbing, and web origin guards."
              actions={
                <Button
                  variant="primary"
                  label="Verify Obligations"
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

  const allClosed = report.summary.failed === 0;

  return (
    <Layout
      padding={6}
      height="fill"
      content={
        <LayoutContent>
          <VStack gap={4}>
            <Card padding={5}>
              <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
                <VStack gap={1.5}>
                  <HStack gap={2} vAlign="center" wrap="wrap">
                    <Heading level={1}>Security &amp; Isolation Obligations</Heading>
                    <Badge
                      variant={allClosed ? "success" : "error"}
                      label={
                        allClosed
                          ? `All ${report.summary.closed}/${report.summary.total} Closed`
                          : `${report.summary.failed} Failed`
                      }
                    />
                    <Code>{report.ledger_id}</Code>
                  </HStack>
                  <Text type="supporting" color="secondary" hasTabularNumbers>
                    Verified live against package modules at {report.verified_at}
                  </Text>
                </VStack>

                <Button
                  variant="secondary"
                  label="Re-verify All"
                  isLoading={loading}
                  onClick={onRefresh}
                />
              </HStack>
            </Card>

            <Card padding={0}>
              <Table
                data={report.items}
                columns={columns}
                idKey="obligation_id"
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
