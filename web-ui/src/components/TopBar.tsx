import { Badge } from "@astryxdesign/core/Badge";
import { Button } from "@astryxdesign/core/Button";
import { useMediaQuery } from "@astryxdesign/core/hooks";
import { HStack } from "@astryxdesign/core/HStack";
import { Icon } from "@astryxdesign/core/Icon";
import { NavIcon } from "@astryxdesign/core/NavIcon";
import { Section } from "@astryxdesign/core/Section";
import { Selector } from "@astryxdesign/core/Selector";
import { Tab, TabList } from "@astryxdesign/core/TabList";
import { Text } from "@astryxdesign/core/Text";
import { Token } from "@astryxdesign/core/Token";
import { TopNav, TopNavHeading } from "@astryxdesign/core/TopNav";
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
  isDarkOnlyTheme: boolean;
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
  isDarkOnlyTheme,
  resolvedMode,
  onViewChange,
  onThemeChange,
  onToggleColorMode,
  onOpenCreate,
}: TopBarProps) {
  const isWide = useMediaQuery("(min-width: 1180px)");
  const hubInstalled = targets?.hub.installed ?? false;
  const ideInstalled = targets?.ide.installed ?? false;

  return (
    <TopNav
      label="Primary console navigation"
      heading={
        <TopNavHeading
          logo={<NavIcon icon={<Icon icon="success" size="sm" />} />}
          heading="agy-profiles"
          subheading={version ? `v${version}` : "local"}
          headerEndContent={
            isWide && root ? (
              <Section variant="transparent" maxWidth={210} padding={0}>
                <Token size="sm" color="gray" label={root} />
              </Section>
            ) : undefined
          }
        />
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
          {isWide && targets ? (
            !hubInstalled && !ideInstalled ? (
              <Badge variant="warning" label="No Targets" />
            ) : (
              <Text type="supporting" color="secondary" hasTabularNumbers>
                {[
                  hubInstalled ? `Hub ${targets.hub.version}` : "Hub missing",
                  ideInstalled ? `IDE ${targets.ide.version}` : "IDE missing",
                ].join(" · ")}
              </Text>
            )
          ) : null}
          <Selector
            label="Console theme"
            isLabelHidden
            size="sm"
            variant="secondary"
            width={156}
            value={themeSlug}
            onChange={(slug) => onThemeChange(slug as ThemeSlug)}
            options={THEME_OPTIONS.map((t) => ({
              value: t.value,
              label: t.label,
              description: t.description,
            }))}
          />
          {!isDarkOnlyTheme ? (
            <Button
              size="sm"
              variant="ghost"
              label={resolvedMode === "dark" ? "Dark" : "Light"}
              tooltip="Toggle light or dark appearance"
              onClick={onToggleColorMode}
            />
          ) : null}
          <Button
            size="sm"
            variant="primary"
            label="New Profile"
            tooltip="Create profile (N)"
            onClick={onOpenCreate}
          />
        </HStack>
      }
    />
  );
}
