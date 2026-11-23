# Watchdog and Post-Logout Session Auto-Recovery

`agy-profiles` includes a zero-dependency 24/7 macOS watchdog (`dev.agy-profiles.watchdog`), a native Rust CPU/GPU/PID guardian (`agyp-guard`), an in-app Antigravity Hub recovery sidecar (`antigravity-plugin/sidecars/console/main.mjs`), the `agyp recover` CLI command, and the `session_recover` MCP tool.

## Why Conversations Stall After Logout and Login

When you log out and sign into another Google account in Google Antigravity Hub to rotate weekly usage limits, Antigravity clears the active `userTier` and model map for a few seconds before `fetchAvailableModels` completes. Any running agent turn or waking `/schedule` automation during that window terminates with one of these errors:

1. `Error Unknown: Agent execution terminated due to error.`
2. `failed to construct executor: unknown model key MODEL_PLACEHOLDER_*: model not found`
3. `You are not logged into Antigravity.`
4. `stream reading error: http2: server sent GOAWAY`

Antigravity writes this final failure as a `CORTEX_STEP_TYPE_ERROR_MESSAGE` step inside live trajectory memory without always flushing it to `transcript.jsonl`, and leaves `latestExecutorTerminationReason` set to `EXECUTOR_TERMINATION_REASON_NO_TOOL_CALL`.

## How `dev.agy-profiles.watchdog` and `agyp recover` Fix It

1. **Live RPC Tail Inspection**: `find_stalled_desktop_conversations()` queries `GetCascadeTrajectorySteps` on the Desktop Hub loopback server for the tail steps of every recent idle conversation, catching hidden `CORTEX_STEP_TYPE_ERROR_MESSAGE` failures even when `transcript.jsonl` ended on `PLANNER_RESPONSE`.
2. **Model Readiness Gate and Safe Fallback**: `parse_quota_summary_buckets()` checks `clientModelConfigs` before dispatching. During the brief post-login window when `clientModelConfigs` is empty, `can_dispatch_now` stays `false` so retries never fire prematurely. Once models load, `select_plan_model_for_conversation()` keeps the conversation's original `generatorModel` if present on the signed-in account, or falls back safely to an available non-exhausted model.
3. **Auth-Transition Ledger Reset and 5-Minute Anti-Storm Cooldown**: Retry tracking is keyed strictly by `<scope>:<cascade_id>` (never `step_count`) with a default `300s` (5-minute) cooldown (`AGY_AUTO_RETRY_COOLDOWN_SEC`), automatic attempt resets when `last_good_step` advances, and an immediate ledger clear whenever the signed-in email (`app_storage.json`) or dispatch readiness transitions after login.
4. **Sanctioned Antigravity `2.34+` Fallback (`agentapi`, `agy models`, and `hooks.json`)**: When Desktop Hub `language_server` hides RPC bridge tokens via stdin, `quota_guard.py` scans transcripts and `.stalled-queue.json`, verifies model health via `agy models`, switches stalled turns to healthy models via `agentapi send-message` (or bounded detached `agy`), and pairs with `antigravity-plugin/hooks.json` (`Stop` capacity retry + `SessionStart` post-login recovery) under a single-flight `.recover.lock` mutex.
5. **Dual Watchdog Loops (`agyp-guard` and Aux Pane Sidecar)**:
   1. **Standalone `launchd` Guardian (`dev.agy-profiles.watchdog`)**: `rust/agyp-guard` runs every `3s` to `5s` under `/usr/bin/caffeinate -i`, monitors `~/Library/Logs/Antigravity/language_server.log`, `app_storage.json` email changes, `503` capacity errors, and `transcript.jsonl` byte offsets, schedules recovery `6s` after auth refresh, debounces error bursts (`20s`), and runs a periodic sweep every `300s`.
   2. **Antigravity Plugin Sidecar (`antigravity-plugin/sidecars/console/main.mjs`)**: Runs inside Antigravity Hub directly with inherited app permissions, triggers `agyp recover --json` every `5` minutes (`AGY_SIDECAR_RECOVERY_INTERVAL_MS`), and triggers `6s` after post-login auth refresh events.
6. **Causal Root Cause Grouping (`incident_stories`)**: Inspired by Datadog Watchdog RCA, simultaneous downstream crashes on the same Hub scope are grouped under canonical root-cause classes (`AUTH_LOGIN_MODEL_GAP`, `ACCOUNT_MODEL_MISSING`, `MODEL_CAPACITY_503`, `HTTP2_STREAM_DROP`, `FIVE_HOUR_QUOTA_PAUSE`, `WEEKLY_QUOTA_EXHAUSTED`, `TOOL_HOOK_INTERRUPT`, `EXECUTION_ERROR`).
7. **Out-of-Band Hash-Chained Audit Receipts (`logs/recovery-audit.jsonl`)**: Inspired by the NVIDIA Open Agent Safety Platform (OpenShell and out-of-band Sentry telemetry), every live recovery writes a `0o600` SHA-256 hash-chained receipt linking `prev_hash` to `receipt_hash` without storing OAuth tokens, email addresses, or prompt text.

## Usage and Verification Commands

1. Install and check the 24/7 macOS `launchd` watchdog and local Web Console:

```bash
agyp daemon install --no-open --json
agyp daemon status --json
```

2. Inspect stalled or crashed Desktop Hub conversations without sending messages:

```bash
agyp recover --dry-run --json
```

3. Force an immediate recovery pass across all reachable Hubs:

```bash
agyp recover --reset-ledger --json
```

4. Launch `agy acp` (for `pi-antigravity-acp-provider` and ACP clients) inside an isolated Google account sandbox:

```bash
agyp agy work-backup -- acp
```

5. Check the live health and `Recover` button inside the Web Console or Antigravity Aux Pane:

```bash
agyp daemon open
```

## Architecture and External References

1. **AI Watchdog (`arXiv:2608.21841`)**: Validates independent, low-friction agent supervision outside the primary LLM executor rather than asking a failing model to police itself.
2. **NVIDIA Open Agent Safety Platform**: Motivates out-of-band process/sandbox boundaries and tamper-evident audit trails (`logs/recovery-audit.jsonl`) isolated from agent memory.
3. **Datadog Watchdog**: Motivates grouping correlated downstream errors into unified `incident_stories` with a single probable root cause (`AUTH_LOGIN_MODEL_GAP`, `ACCOUNT_MODEL_MISSING`).
4. **Agent Client Protocol (`agy acp` and `pi-antigravity-acp-provider`)**: Isolating `HOME` and `.zshenv` per profile lets any ACP client or coding harness run multiple Google Antigravity accounts cleanly on macOS.
