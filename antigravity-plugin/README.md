# AGY Profiles Antigravity Plugin

Native plugin bundle integrating `agy-profiles` directly inside Google Antigravity Hub and Antigravity IDE.

## Provided Capabilities

1. **Aux Pane Console & Recovery Sidecar (`sidecars/console`)**: Runs the hardened loopback `agy-profiles web` console inside Antigravity's side pane plus a built-in 5-minute and post-login (`auth_refresh`) recovery pass so crashed sessions auto-resume directly inside Antigravity Hub without terminal intervention.
2. **MCP Server (`mcp_config.json`)**: Exposes all 18 `agy-profiles` tools cleanly over stdio JSON-RPC 2.0 (`profile_list`, `profile_inspect`, `profile_create`, `profile_update`, `profile_launch`, `profile_stop`, `profile_repair`, `profile_clone`, `profile_rename`, `profile_delete`, `launcher_build`, `launcher_remove`, `profile_sync`, `profile_switch`, `host_handoff`, `system_doctor`, `obligations_verify`, `session_recover`).
3. **24/7 Watchdog & 5-Minute Auto-Recovery (`agyp-guard`)**: Monitors `language_server.log`, transcript logs, and live Desktop Hub trajectories every 5 minutes (plus 6 seconds after re-login) to automatically resume threads stopped by logout/login auth refresh, missing model keys, stream drops, or 5-hour quota exhaustion.
4. **Operator Skill (`skills/agy-profiles/SKILL.md`)**: Guides Antigravity agents through clean sandbox provisioning, Automations migration modes, bidirectional handoff, post-login session recovery, and safe quota switchover.

## Installation

Install the plugin bundle symlink alongside CLI shims from the repository root:

```bash
./install.sh --with-skill --with-plugin
```
