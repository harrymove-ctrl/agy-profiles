# AGY Profiles Antigravity Plugin

Native plugin bundle integrating `agy-profiles` directly inside Google Antigravity Hub and Antigravity IDE.

## Provided Capabilities

1. **Aux Pane Console Sidecar (`sidecars/console`)**: Runs the hardened loopback `agy-profiles web` console inside Antigravity's side pane so you can launch, sync, pause or activate Automations, rename, clone, and switch quota across isolated Google accounts without opening a terminal.
2. **MCP Server (`mcp_config.json`)**: Exposes all 17 `agy-profiles` tools cleanly over stdio JSON-RPC 2.0 (`profile_list`, `profile_inspect`, `profile_create`, `profile_update`, `profile_launch`, `profile_stop`, `profile_repair`, `profile_clone`, `profile_rename`, `profile_delete`, `launcher_build`, `launcher_remove`, `profile_sync`, `profile_switch`, `host_handoff`, `system_doctor`, `obligations_verify`).
3. **Operator Skill (`skills/agy-profiles/SKILL.md`)**: Guides Antigravity agents through clean sandbox provisioning, Automations migration modes, bidirectional handoff, and safe quota switchover.

## Installation

Install the plugin bundle symlink alongside CLI shims from the repository root:

```bash
./install.sh --with-skill --with-plugin
```
