import { useEffect, useState } from "react";
import { Banner } from "@astryxdesign/core/Banner";
import { Button } from "@astryxdesign/core/Button";
import { CheckboxInput } from "@astryxdesign/core/CheckboxInput";
import { Code } from "@astryxdesign/core/Code";
import { Drawer, DrawerHeader } from "@astryxdesign/core/Drawer";
import { FormLayout } from "@astryxdesign/core/FormLayout";
import { HStack } from "@astryxdesign/core/HStack";
import { Layout, LayoutContent } from "@astryxdesign/core/Layout";
import { Selector } from "@astryxdesign/core/Selector";
import { Switch } from "@astryxdesign/core/Switch";
import { Text } from "@astryxdesign/core/Text";
import { TextInput } from "@astryxdesign/core/TextInput";
import { VStack } from "@astryxdesign/core/VStack";
import { ACCENT_PRESETS } from "../api";
import type {
  AuthMode,
  CloneProfilePayload,
  CreateProfilePayload,
  LinkPolicy,
  TargetKind,
} from "../types";

export interface CreateProfileDrawerProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (payload: CreateProfilePayload) => Promise<void>;
}

export function CreateProfileDrawer({
  isOpen,
  onOpenChange,
  onCreate,
}: CreateProfileDrawerProps) {
  const [name, setName] = useState("");
  const [label, setLabel] = useState("");
  const [accent, setAccent] = useState(ACCENT_PRESETS[0].hex);
  const [defaultTarget, setDefaultTarget] = useState<TargetKind>("hub");
  const [linkPolicy, setLinkPolicy] = useState<LinkPolicy>("minimal");
  const [authMode, setAuthMode] = useState<AuthMode>("isolated-file");
  const [inheritConfig, setInheritConfig] = useState(false);
  const [keepBg, setKeepBg] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setName("");
      setLabel("");
      setAccent(ACCENT_PRESETS[0].hex);
      setDefaultTarget("hub");
      setLinkPolicy("minimal");
      setAuthMode("isolated-file");
      setInheritConfig(false);
      setKeepBg(false);
      setErrorMsg(null);
    }
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const slug = name.trim();
    if (!slug) {
      setErrorMsg("Enter a valid profile slug (letters, digits, dot, underscore, hyphen).");
      return;
    }
    setSubmitting(true);
    setErrorMsg(null);
    try {
      await onCreate({
        name: slug,
        label: label.trim() || undefined,
        accent,
        default_target: defaultTarget,
        link_policy: linkPolicy,
        auth_mode: authMode,
        keep_background_alive: keepBg,
        inherit_config: inheritConfig,
      });
      onOpenChange(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to create profile.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      label="Create Sandbox Profile"
      side="end"
      width={460}
      purpose="form"
    >
      <Layout
        header={
          <DrawerHeader
            title="Create Sandbox Profile"
            subtitle="Provision an isolated directory with 0700 permissions and dedicated OAuth state."
            onOpenChange={onOpenChange}
          />
        }
        content={
          <LayoutContent>
            <form id="agyp-create-form" onSubmit={handleSubmit}>
              <VStack gap={4}>
                {errorMsg ? (
                  <Banner
                    status="error"
                    title="Unable to create profile"
                    description={errorMsg}
                  />
                ) : null}
                <FormLayout direction="vertical">
                  <TextInput
                    label="Profile Slug"
                    description="1 to 48 ASCII letters, numbers, dots, underscores, or hyphens."
                    placeholder="client-work"
                    value={name}
                    onChange={setName}
                    isRequired
                  />
                  <TextInput
                    label="Display Label"
                    placeholder="Client Work"
                    value={label}
                    onChange={setLabel}
                  />
                  <VStack gap={1.5}>
                    <HStack hAlign="between" vAlign="center">
                      <Text type="label">Profile Accent</Text>
                      <Code>{accent}</Code>
                    </HStack>
                    <div
                      className="agyp-swatch-row"
                      role="radiogroup"
                      aria-label="New profile accent color"
                    >
                      {ACCENT_PRESETS.map((preset) => {
                        const selected =
                          accent.toUpperCase() === preset.hex.toUpperCase();
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
                            onClick={() => setAccent(preset.hex)}
                          />
                        );
                      })}
                    </div>
                  </VStack>
                  <Selector
                    label="Default Target"
                    value={defaultTarget}
                    onChange={(v) => setDefaultTarget(v as TargetKind)}
                    options={[
                      { value: "hub", label: "Antigravity Hub" },
                      { value: "ide", label: "Antigravity IDE" },
                    ]}
                  />
                  <Selector
                    label="Symlink Policy"
                    value={linkPolicy}
                    onChange={(v) => setLinkPolicy(v as LinkPolicy)}
                    options={[
                      { value: "none", label: "none (Zero host links)" },
                      { value: "minimal", label: "minimal (Fonts and safe caches)" },
                      { value: "dev", label: "dev (Toolchain caches)" },
                    ]}
                  />
                  <Selector
                    label="Auth Storage Mode"
                    value={authMode}
                    onChange={(v) => setAuthMode(v as AuthMode)}
                    options={[
                      {
                        value: "isolated-file",
                        label: "isolated-file (Isolated sandbox token)",
                      },
                      {
                        value: "system-keychain",
                        label: "system-keychain (Shared login keychain)",
                      },
                    ]}
                  />
                  <CheckboxInput
                    label="Inherit sanitized host GEMINI.md and MCP config"
                    description="Fails closed if JSON is malformed; tokens and API keys are redacted."
                    value={inheritConfig}
                    onChange={(checked) => setInheritConfig(checked)}
                  />
                  <Switch
                    label="Keep background helper processes alive on close"
                    value={keepBg}
                    onChange={(checked) => setKeepBg(checked)}
                  />
                </FormLayout>
              </VStack>
            </form>
          </LayoutContent>
        }
        footer={
          <HStack gap={2} hAlign="end">
            <Button
              variant="ghost"
              label="Cancel"
              isDisabled={submitting}
              onClick={() => onOpenChange(false)}
            />
            <Button
              type="submit"
              form="agyp-create-form"
              variant="primary"
              label="Create Profile"
              isLoading={submitting}
            />
          </HStack>
        }
      />
    </Drawer>
  );
}

export interface CloneProfileDrawerProps {
  sourceName: string | null;
  sourceLabel: string | null;
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  onClone: (source: string, payload: CloneProfilePayload) => Promise<void>;
}

export function CloneProfileDrawer({
  sourceName,
  sourceLabel,
  isOpen,
  onOpenChange,
  onClone,
}: CloneProfileDrawerProps) {
  const [target, setTarget] = useState("");
  const [label, setLabel] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && sourceName) {
      setTarget(`${sourceName}-copy`);
      setLabel(sourceLabel ? `${sourceLabel} Copy` : "");
      setErrorMsg(null);
    }
  }, [isOpen, sourceName, sourceLabel]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sourceName) {
      return;
    }
    const slug = target.trim();
    if (!slug) {
      setErrorMsg("Enter a destination profile slug.");
      return;
    }
    setSubmitting(true);
    setErrorMsg(null);
    try {
      await onClone(sourceName, {
        target: slug,
        label: label.trim() || undefined,
      });
      onOpenChange(false);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to clone profile.");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      label="Clone Sandbox Profile"
      side="end"
      width={440}
      purpose="form"
    >
      <Layout
        header={
          <DrawerHeader
            title="Clone Sandbox Profile"
            subtitle="Copy a stopped sandbox cleanly while skipping transient locks and symlinks."
            onOpenChange={onOpenChange}
          />
        }
        content={
          <LayoutContent>
            <form id="agyp-clone-form" onSubmit={handleSubmit}>
              <VStack gap={4}>
                {errorMsg ? (
                  <Banner
                    status="error"
                    title="Unable to clone profile"
                    description={errorMsg}
                  />
                ) : null}
                <HStack gap={2} vAlign="center">
                  <Text type="label">Source profile:</Text>
                  <Code>{sourceName ?? ""}</Code>
                </HStack>
                <FormLayout direction="vertical">
                  <TextInput
                    label="Target Profile Slug"
                    value={target}
                    onChange={setTarget}
                    isRequired
                  />
                  <TextInput
                    label="Target Display Label"
                    value={label}
                    onChange={setLabel}
                  />
                </FormLayout>
              </VStack>
            </form>
          </LayoutContent>
        }
        footer={
          <HStack gap={2} hAlign="end">
            <Button
              variant="ghost"
              label="Cancel"
              isDisabled={submitting}
              onClick={() => onOpenChange(false)}
            />
            <Button
              type="submit"
              form="agyp-clone-form"
              variant="primary"
              label="Clone Profile"
              isLoading={submitting}
            />
          </HStack>
        }
      />
    </Drawer>
  );
}
