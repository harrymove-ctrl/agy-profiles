import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Card } from "@astryxdesign/core/Card";
import { Code } from "@astryxdesign/core/Code";
import { EmptyState } from "@astryxdesign/core/EmptyState";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent, LayoutHeader } from "@astryxdesign/core/Layout";
import { StatusDot } from "@astryxdesign/core/StatusDot";
import { Table, pixel, proportional, type TableColumn } from "@astryxdesign/core/Table";
import { Text } from "@astryxdesign/core/Text";
import { Timestamp } from "@astryxdesign/core/Timestamp";
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
            label={closed ? "Verified" : "Failed"}
          />
          {closed ? (
            <Text weight="medium">Verified</Text>
          ) : (
            <Badge variant="error" label="Failed" />
          )}
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
                  ? "Verifying obligations..."
                  : "Obligation report unavailable"
              }
              description="Run live checks on slug rules, path containment, symlinks, redaction, and CSRF."
              actions={
                <Button
                  variant="primary"
                  label="Run Checks"
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
      header={
        <LayoutHeader hasDivider>
          <HStack hAlign="between" vAlign="center" gap={4} wrap="wrap">
            <VStack gap={1}>
              <HStack gap={2} vAlign="center" wrap="wrap">
                <Heading level={1}>Security Obligations</Heading>
                <StatusDot
                  variant={allClosed ? "success" : "error"}
                  label={allClosed ? "All verified" : "Failed"}
                />
                {report.summary.failed > 0 ? (
                  <Badge
                    variant="error"
                    label={`${report.summary.failed} Failed`}
                  />
                ) : null}
              </HStack>
              <Text type="supporting" color="secondary" hasTabularNumbers>
                {report.summary.closed} of {report.summary.total} verified ·{" "}
                {report.ledger_id} ·{" "}
                <Timestamp
                  value={report.verified_at}
                  format="date_time"
                  timezoneID="UTC"
                  isTimezoneShown
                />
              </Text>
            </VStack>

            <Button
              size="sm"
              variant="secondary"
              label="Run Checks"
              tooltip="Re-run checks (R)"
              isLoading={loading}
              onClick={onRefresh}
            />
          </HStack>
        </LayoutHeader>
      }
      content={
        <LayoutContent>
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
        </LayoutContent>
      }
    />
  );
}
