import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { Code } from "@astryxdesign/core/Code";
import { Heading } from "@astryxdesign/core/Heading";
import { HStack } from "@astryxdesign/core/HStack";
import { Selector } from "@astryxdesign/core/Selector";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { TopNav } from "@astryxdesign/core/TopNav";
import type { ThemeSlug } from "../astryx-themes";
import { THEME_OPTIONS } from "../api";
import type { AppView, TargetInfo } from "../types";

export interface TopBarProps {
  version: string;
  root: string;
  view: AppView;
  profileCount: number;
  targets: { hub: TargetInfo; ide: TargetInfo } | null;
  themeSlug: ThemeSlug;
  resolvedMode: "light" | "dark";
  onViewChange: (view: AppView) => void;
  onThemeChange: (slug: ThemeSlug) => void;
  onToggleColorMode: () => void;
  onOpenCreate: () => void;
}

export function TopBar({
  version,
  root,
  view,
  profileCount,
  targets,
  themeSlug,
  resolvedMode,
  onViewChange,
  onThemeChange,
  onToggleColorMode,
  onOpenCreate,
}: TopBarProps) {
  const hubInstalled = targets?.hub.installed ?? false;
  const ideInstalled = targets?.ide.installed ?? false;

  return (
    <TopNav
      label="Primary console navigation"
      heading={
        <HStack gap={2} vAlign="center">
          <img src="/mark.svg" alt="" width={28} height={28} />
          <Heading level={4}>agy-profiles</Heading>
          <Badge variant="neutral" label={version ? `v${version}` : "local"} />
          {root ? (
            <span className="agyp-root-chip" title={root}>
              <Code color="secondary">{root}</Code>
            </span>
          ) : null}
        </HStack>
      }
      centerContent={
        <TabList
          value={view}
          onChange={(next) => onViewChange(next as AppView)}
          size="md"
        >
          <Tab value="profiles" label={`Profiles (${profileCount})`} />
          <Tab value="obligations" label="Obligations" />
          <Tab value="doctor" label="Doctor" />
        </TabList>
      }
      endContent={
        <HStack gap={2} vAlign="center" wrap="wrap">
          {targets ? (
            <HStack gap={1.5} vAlign="center" className="agyp-target-badges">
              <Badge
                variant={hubInstalled ? "success" : "warning"}
                label={hubInstalled ? `Hub ${targets.hub.version}` : "Hub Missing"}
              />
              <Badge
                variant={ideInstalled ? "info" : "warning"}
                label={ideInstalled ? `IDE ${targets.ide.version}` : "IDE Missing"}
              />
            </HStack>
          ) : null}
          <Selector
            label="Console theme"
            isLabelHidden
            size="sm"
            variant="secondary"
            width={142}
            value={themeSlug}
            onChange={(slug) => onThemeChange(slug as ThemeSlug)}
            options={THEME_OPTIONS.map((t) => ({
              value: t.value,
              label: t.label,
              description: t.description,
            }))}
          />
          <Button
            size="sm"
            variant="secondary"
            label={
              themeSlug === "gothic"
                ? "Dark"
                : resolvedMode === "dark"
                  ? "Dark"
                  : "Light"
            }
            tooltip={
              themeSlug === "gothic"
                ? "Gothic theme uses dark mode"
                : "Toggle light or dark appearance"
            }
            isDisabled={themeSlug === "gothic"}
            onClick={onToggleColorMode}
          />
          <Button
            size="sm"
            variant="primary"
            label="New Profile"
            onClick={onOpenCreate}
          />
        </HStack>
      }
    />
  );
}
