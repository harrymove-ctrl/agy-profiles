(() => {
  "use strict";

  const DEFAULT_ACCENTS = [
    "#3B82F6",
    "#10B981",
    "#F59E0B",
    "#EC4899",
    "#8B5CF6",
    "#06B6D4",
  ];

  const appState = {
    view: "profiles",
    filter: "all",
    query: "",
    selectedName: null,
    overview: null,
    detail: null,
    obligations: null,
    doctor: null,
    confirmDeleteName: null,
    busy: false,
  };

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="agy-csrf"]');
    return meta ? meta.getAttribute("content") || "" : "";
  }

  function stripBootstrapTokenFromUrl() {
    if (window.location.search && window.location.search.indexOf("token=") !== -1) {
      window.history.replaceState({}, "", window.location.pathname || "/");
    }
  }

  function el(tag, className, textContent) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (textContent !== undefined && textContent !== null) {
      node.textContent = String(textContent);
    }
    return node;
  }

  function profileInitials(text) {
    const words = String(text || "").trim().split(/\s+/).filter(Boolean);
    if (words.length >= 2) {
      return (words[0][0] + words[1][0]).toUpperCase();
    }
    return String(text || "AG").slice(0, 2).toUpperCase();
  }

  function clearNode(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function formatBytes(bytes) {
    const num = Number(bytes) || 0;
    if (num < 1024) return num + " B";
    if (num < 1024 * 1024) return (num / 1024).toFixed(1) + " KiB";
    if (num < 1024 * 1024 * 1024) return (num / (1024 * 1024)).toFixed(1) + " MiB";
    return (num / (1024 * 1024 * 1024)).toFixed(2) + " GiB";
  }

  function showToast(message, kind) {
    const region = document.getElementById("toast-region");
    if (!region) return;
    const toast = el("div", "toast " + (kind === "error" ? "toast-error" : "toast-success"), message);
    region.appendChild(toast);
    window.setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 4200);
  }

  async function apiFetch(path, options) {
    const opts = options ? Object.assign({}, options) : {};
    const headers = Object.assign(
      {
        "X-AGY-CSRF": getCsrfToken(),
      },
      opts.headers || {}
    );
    if (opts.body !== undefined && typeof opts.body !== "string") {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    opts.headers = headers;
    opts.credentials = "same-origin";

    const response = await fetch(path, opts);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const err = data && data.error ? data.error : {};
      const msg = err.message || ("HTTP " + response.status);
      const rem = err.remediation ? " " + err.remediation : "";
      throw new Error(msg + rem);
    }
    return data;
  }

  function computeCombinedState(profileSummary) {
    const hubState = profileSummary.runtime && profileSummary.runtime.hub ? profileSummary.runtime.hub.state : "stopped";
    const ideState = profileSummary.runtime && profileSummary.runtime.ide ? profileSummary.runtime.ide.state : "stopped";
    if (hubState === "running" || ideState === "running") {
      return "running";
    }
    if (hubState === "stale-lock" || ideState === "stale-lock") {
      return "stale";
    }
    return "stopped";
  }

  function makeStatePill(stateValue) {
    if (stateValue === "running") {
      return el("span", "pill pill-green", "Running");
    }
    if (stateValue === "stale" || stateValue === "stale-lock") {
      return el("span", "pill pill-amber", "Stale Lock");
    }
    return el("span", "pill pill-muted", "Stopped");
  }

  function initTheme() {
    const stored = window.localStorage.getItem("agyp-theme");
    const theme = stored === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", theme);
    const btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.addEventListener("click", () => {
        const current = document.documentElement.getAttribute("data-theme");
        const next = current === "light" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        window.localStorage.setItem("agyp-theme", next);
      });
    }
  }

  function buildAccentPicker() {
    const picker = document.getElementById("create-accent-picker");
    const hidden = document.getElementById("create-accent-value");
    if (!picker || !hidden) return;
    clearNode(picker);
    DEFAULT_ACCENTS.forEach((hex, idx) => {
      const btn = el("button", "accent-swatch" + (idx === 0 ? " is-selected" : ""));
      btn.type = "button";
      btn.style.backgroundColor = hex;
      btn.setAttribute("aria-label", "Color " + hex);
      btn.addEventListener("click", () => {
        hidden.value = hex;
        Array.from(picker.children).forEach((child) => child.classList.remove("is-selected"));
        btn.classList.add("is-selected");
      });
      picker.appendChild(btn);
    });
  }

  function openDrawer(drawerId) {
    const backdrop = document.getElementById("drawer-backdrop");
    const drawer = document.getElementById(drawerId);
    if (backdrop) backdrop.classList.remove("is-hidden");
    if (drawer) drawer.classList.remove("is-hidden");
  }

  function closeAllDrawers() {
    const backdrop = document.getElementById("drawer-backdrop");
    if (backdrop) backdrop.classList.add("is-hidden");
    document.querySelectorAll(".drawer").forEach((node) => {
      node.classList.add("is-hidden");
    });
  }

  function renderHeaderMeta() {
    if (!appState.overview) return;
    const versionBadge = document.getElementById("version-badge");
    const rootChip = document.getElementById("root-path-badge");
    const targetsStrip = document.getElementById("targets-strip");

    if (versionBadge && appState.overview.server) {
      versionBadge.textContent = "v" + (appState.overview.server.version || "0.1.0");
    }
    if (rootChip) {
      rootChip.textContent = appState.overview.root || "";
      rootChip.title = "Profile storage root: " + (appState.overview.root || "");
    }
    if (targetsStrip) {
      clearNode(targetsStrip);
      const targets = appState.overview.targets || {};
      const hub = targets.hub || {};
      const ide = targets.ide || {};
      targetsStrip.appendChild(
        el(
          "span",
          "pill " + (hub.installed ? "pill-green" : "pill-amber"),
          hub.installed ? "Hub " + (hub.version || "ready") : "Hub missing"
        )
      );
      targetsStrip.appendChild(
        el(
          "span",
          "pill " + (ide.installed ? "pill-blue" : "pill-muted"),
          ide.installed ? "IDE " + (ide.version || "ready") : "IDE optional"
        )
      );
    }
  }

  function getFilteredProfiles() {
    const all = (appState.overview && appState.overview.profiles) || [];
    const q = appState.query.trim().toLowerCase();
    return all.filter((item) => {
      const m = item.manifest || {};
      const combined = computeCombinedState(item);
      if (appState.filter !== "all" && combined !== appState.filter) {
        return false;
      }
      if (!q) return true;
      return (
        String(m.name || "").toLowerCase().indexOf(q) !== -1 ||
        String(m.label || "").toLowerCase().indexOf(q) !== -1
      );
    });
  }

  function renderSidebar() {
    const listEl = document.getElementById("profile-list");
    if (!listEl) return;
    clearNode(listEl);
    const profiles = getFilteredProfiles();

    if (profiles.length === 0) {
      const emptyNote = el("p", "muted-text", "No matching profiles.");
      emptyNote.style.padding = "12px";
      listEl.appendChild(emptyNote);
      return;
    }

    profiles.forEach((item) => {
      const m = item.manifest || {};
      const combined = computeCombinedState(item);
      const btn = el(
        "button",
        "profile-item" + (m.name === appState.selectedName ? " is-selected" : "")
      );
      btn.type = "button";
      btn.setAttribute("role", "option");
      btn.setAttribute("aria-selected", m.name === appState.selectedName ? "true" : "false");

      const top = el("div", "profile-item-top");
      const titleWrap = el("div", "profile-title-wrap");
      const dot = el("span", "accent-dot");
      dot.style.backgroundColor = m.accent || "#3B82F6";
      titleWrap.appendChild(dot);
      titleWrap.appendChild(el("span", "profile-label", m.label || m.name));
      top.appendChild(titleWrap);
      top.appendChild(makeStatePill(combined));

      const meta = el("div", "profile-item-meta");
      meta.appendChild(el("span", "mono", m.name));
      meta.appendChild(
        el("span", "tabular", (m.default_target || "hub") + " · " + formatBytes(item.disk_bytes))
      );

      btn.appendChild(top);
      btn.appendChild(meta);
      btn.addEventListener("click", () => {
        appState.confirmDeleteName = null;
        selectProfile(m.name);
      });
      listEl.appendChild(btn);
    });
  }

  async function selectProfile(name) {
    appState.selectedName = name;
    renderSidebar();
    if (!name) {
      appState.detail = null;
      renderDetailStage();
      return;
    }
    try {
      appState.detail = await apiFetch("/api/profiles/" + encodeURIComponent(name));
      renderDetailStage();
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  function renderDetailStage() {
    const stage = document.getElementById("detail-stage");
    if (!stage) return;
    clearNode(stage);

    const allProfiles = (appState.overview && appState.overview.profiles) || [];
    if (allProfiles.length === 0) {
      const card = el("div", "card empty-card");
      card.appendChild(el("h2", "", "No sandbox profiles created yet"));
      card.appendChild(
        el(
          "p",
          "muted-text",
          "Create an isolated profile directory with 0700 permissions, locked shell HOME, and zero secret leaks."
        )
      );
      const createBtn = el("button", "btn btn-primary", "Create First Sandbox Profile");
      createBtn.type = "button";
      createBtn.addEventListener("click", () => openDrawer("create-drawer"));
      card.appendChild(createBtn);
      stage.appendChild(card);
      return;
    }

    const detail = appState.detail;
    if (!detail || !detail.manifest) {
      const loading = el("div", "card empty-card");
      loading.appendChild(el("p", "muted-text", "Select a profile from the sidebar to inspect."));
      stage.appendChild(loading);
      return;
    }

    const m = detail.manifest;
    const rt = detail.runtime || {};
    const hubRt = rt.hub || { state: "stopped", pids: [], locks: [] };
    const ideRt = rt.ide || { state: "stopped", pids: [], locks: [] };
    const iso = detail.isolation || {};
    const ev = detail.evidence || {};
    const launchers = detail.launchers || {};
    const paths = detail.paths || {};
    const combinedState = computeCombinedState(detail);
    const totalPids = (hubRt.pids || []).length + (ideRt.pids || []).length;
    const hasStaleLocks = hubRt.state === "stale-lock" || ideRt.state === "stale-lock";

    // Hero Card
    const hero = el("section", "card hero-card");
    const ident = el("div", "hero-identity");
    const badge = el("div", "hero-badge", profileInitials(m.label || m.name));
    badge.style.backgroundColor = m.accent || "#3B82F6";

    const titles = el("div", "hero-titles");
    titles.appendChild(el("h1", "", m.label || m.name));
    const sub = el("div", "hero-subline");
    sub.appendChild(el("span", "mono", m.name));
    sub.appendChild(makeStatePill(combinedState));
    sub.appendChild(
      el("span", "pill pill-muted tabular", totalPids + (totalPids === 1 ? " process" : " processes"))
    );
    sub.appendChild(el("span", "pill pill-blue", m.auth_mode || "isolated-file"));
    titles.appendChild(sub);

    ident.appendChild(badge);
    ident.appendChild(titles);

    const actions = el("div", "hero-actions");

    const launchHubBtn = el("button", "btn btn-primary", "Launch Hub");
    launchHubBtn.type = "button";
    launchHubBtn.addEventListener("click", () => runProfileAction(m.name, "launch", { target: "hub" }));
    actions.appendChild(launchHubBtn);

    const launchIdeBtn = el("button", "btn btn-secondary", "Launch IDE");
    launchIdeBtn.type = "button";
    launchIdeBtn.addEventListener("click", () => runProfileAction(m.name, "launch", { target: "ide" }));
    actions.appendChild(launchIdeBtn);

    if (combinedState === "running") {
      const stopBtn = el("button", "btn btn-warn", "Stop");
      stopBtn.type = "button";
      stopBtn.addEventListener("click", () => runProfileAction(m.name, "stop", { target: "all" }));
      actions.appendChild(stopBtn);
    }

    const repairBtn = el("button", hasStaleLocks ? "btn btn-warn" : "btn btn-secondary", "Repair");
    repairBtn.type = "button";
    repairBtn.addEventListener("click", () => runProfileAction(m.name, "repair", {}));
    actions.appendChild(repairBtn);

    const cloneBtn = el("button", "btn btn-secondary", "Clone");
    cloneBtn.type = "button";
    cloneBtn.addEventListener("click", () => {
      document.getElementById("clone-source").value = m.name;
      document.getElementById("clone-target").value = "";
      document.getElementById("clone-label").value = (m.label || m.name) + " Copy";
      openDrawer("clone-drawer");
    });
    actions.appendChild(cloneBtn);

    const defaultTargetHasLauncher = Boolean(launchers[m.default_target || "hub"]);
    const launcherBtn = el(
      "button",
      "btn btn-secondary",
      defaultTargetHasLauncher ? "Remove Launcher" : "Build Launcher"
    );
    launcherBtn.type = "button";
    launcherBtn.addEventListener("click", () =>
      runProfileAction(m.name, "launcher", {
        target: m.default_target || "hub",
        action: defaultTargetHasLauncher ? "remove" : "build",
      })
    );
    actions.appendChild(launcherBtn);

    if (appState.confirmDeleteName === m.name) {
      const confirmBar = el("div", "confirm-bar");
      const confirmBtn = el("button", "btn btn-danger", "Confirm Delete");
      confirmBtn.type = "button";
      confirmBtn.addEventListener("click", () => deleteProfile(m.name));
      const cancelBtn = el("button", "btn btn-ghost", "Cancel");
      cancelBtn.type = "button";
      cancelBtn.addEventListener("click", () => {
        appState.confirmDeleteName = null;
        renderDetailStage();
      });
      confirmBar.appendChild(confirmBtn);
      confirmBar.appendChild(cancelBtn);
      actions.appendChild(confirmBar);
    } else {
      const delBtn = el("button", "btn btn-danger", "Delete");
      delBtn.type = "button";
      delBtn.addEventListener("click", () => {
        appState.confirmDeleteName = m.name;
        renderDetailStage();
      });
      actions.appendChild(delBtn);
    }

    hero.appendChild(ident);
    hero.appendChild(actions);
    stage.appendChild(hero);

    // Metrics Strip
    const metrics = el("section", "metrics-grid");
    const metricItems = [
      { label: "Disk Footprint", value: formatBytes(detail.disk_bytes), cls: "tabular" },
      { label: "Hub Runtime", value: hubRt.state + (hubRt.pids.length ? " (" + hubRt.pids.length + ")" : ""), cls: "mono" },
      { label: "IDE Runtime", value: ideRt.state + (ideRt.pids.length ? " (" + ideRt.pids.length + ")" : ""), cls: "mono" },
      {
        label: "macOS Launchers",
        value:
          (launchers.hub ? "Hub Ready" : "Hub None") +
          " · " +
          (launchers.ide ? "IDE Ready" : "IDE None"),
        cls: "",
      },
    ];
    metricItems.forEach((mi) => {
      const mc = el("div", "metric-card");
      mc.appendChild(el("span", "metric-label", mi.label));
      mc.appendChild(el("span", "metric-value " + mi.cls, mi.value));
      metrics.appendChild(mc);
    });
    stage.appendChild(metrics);

    // Two Column Operational Grid
    const grid = el("section", "two-col-grid");

    // Left Card: Isolation & Policy
    const policyCard = el("div", "card");
    const policyHead = el("div", "card-title-row");
    policyHead.appendChild(el("h2", "", "Isolation & Policy"));
    policyHead.appendChild(
      el(
        "span",
        "pill " + (iso.zshenv_home_locked ? "pill-green" : "pill-red"),
        iso.zshenv_home_locked ? ".zshenv HOME Locked" : "HOME Lock Missing"
      )
    );
    policyCard.appendChild(policyHead);

    const policyForm = el("form", "form-grid");
    const labelField = el("div", "field");
    labelField.appendChild(el("label", "", "Display Label"));
    const labelInput = el("input");
    labelInput.type = "text";
    labelInput.value = m.label || m.name;
    labelField.appendChild(labelInput);
    policyForm.appendChild(labelField);

    const row1 = el("div", "field-row");
    const targetField = el("div", "field");
    targetField.appendChild(el("label", "", "Default Target"));
    const targetSelect = el("select");
    [["hub", "Antigravity Hub"], ["ide", "Antigravity IDE"]].forEach(([val, txt]) => {
      const opt = el("option", "", txt);
      opt.value = val;
      if (m.default_target === val) opt.selected = true;
      targetSelect.appendChild(opt);
    });
    targetField.appendChild(targetSelect);

    const linkField = el("div", "field");
    linkField.appendChild(el("label", "", "Symlink Policy"));
    const linkSelect = el("select");
    [
      ["minimal", "minimal"],
      ["none", "none"],
      ["dev", "dev"],
    ].forEach(([val, txt]) => {
      const opt = el("option", "", txt);
      opt.value = val;
      if (m.link_policy === val) opt.selected = true;
      linkSelect.appendChild(opt);
    });
    linkField.appendChild(linkSelect);
    row1.appendChild(targetField);
    row1.appendChild(linkField);
    policyForm.appendChild(row1);

    const authField = el("div", "field");
    authField.appendChild(el("label", "", "Auth Mode"));
    const authSelect = el("select");
    [
      ["isolated-file", "isolated-file"],
      ["system-keychain", "system-keychain"],
    ].forEach(([val, txt]) => {
      const opt = el("option", "", txt);
      opt.value = val;
      if (m.auth_mode === val) opt.selected = true;
      authSelect.appendChild(opt);
    });
    authField.appendChild(authSelect);
    policyForm.appendChild(authField);

    const bgWrap = el("label", "checkbox-field");
    const bgCheckbox = el("input");
    bgCheckbox.type = "checkbox";
    bgCheckbox.checked = Boolean(m.keep_background_alive);
    bgWrap.appendChild(bgCheckbox);
    bgWrap.appendChild(el("span", "", "Keep background daemon alive on Hub close"));
    policyForm.appendChild(bgWrap);

    const saveBtn = el("button", "btn btn-primary", "Save Policy");
    saveBtn.type = "submit";
    policyForm.appendChild(saveBtn);
    policyForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      try {
        await apiFetch("/api/profiles/" + encodeURIComponent(m.name), {
          method: "PATCH",
          body: {
            label: labelInput.value,
            default_target: targetSelect.value,
            link_policy: linkSelect.value,
            auth_mode: authSelect.value,
            keep_background_alive: bgCheckbox.checked,
          },
        });
        showToast("Updated policy for " + m.name + ".", "success");
        await refreshAll(m.name);
      } catch (err) {
        showToast(err.message, "error");
      }
    });
    policyCard.appendChild(policyForm);

    const permsKv = el("div", "kv-table");
    const perms = iso.permissions || {};
    const forbidden = iso.forbidden_symlinks_present || [];
    const activeLinks = iso.active_symlinks || [];
    [
      ["Profile / Data Mode", (perms.profile_dir || "?") + " / " + (perms.data_dir || "?")],
      ["Sandbox HOME Mode", perms.sandbox_home || "?"],
      ["OAuth Token File", iso.oauth_token_present ? (perms.oauth_token_file || "present") : "not signed in"],
      ["MCP Config Mode", perms.mcp_config_file || "none"],
      ["Forbidden Symlinks", forbidden.length ? forbidden.join(", ") : "0 detected"],
      [
        "Active Host Links",
        activeLinks.length ? activeLinks.map((x) => x.relpath).join(", ") : "none",
      ],
    ].forEach(([k, v]) => {
      const row = el("div", "kv-row");
      row.appendChild(el("span", "kv-key", k));
      row.appendChild(el("span", "kv-val mono", v));
      permsKv.appendChild(row);
    });
    policyCard.appendChild(permsKv);
    grid.appendChild(policyCard);

    // Right Card: Evidence & Security Ledger
    const evCard = el("div", "card");
    const evHead = el("div", "card-title-row");
    evHead.appendChild(el("h2", "", "Evidence & Security Ledger"));
    evHead.appendChild(el("span", "pill pill-blue mono", ev.evidence_id || "ev_local"));
    evCard.appendChild(evHead);

    evCard.appendChild(el("p", "muted-text", ev.summary || "Live inspection summary."));

    const evKv = el("div", "kv-table");
    [
      ["Authority / Confidence", (ev.authority || "filesystem") + " / " + (ev.confidence || "observed")],
      ["Observed At", ev.observed_at || ev.captured_at || ""],
      ["Profile Directory", paths.profile_dir || ""],
      ["Hub User Data", paths.data_dir || ""],
      ["IDE User Data", paths.ide_data_dir || ""],
      ["Sandbox HOME", paths.sandbox_home || ""],
    ].forEach(([k, v]) => {
      const row = el("div", "kv-row");
      row.appendChild(el("span", "kv-key", k));
      row.appendChild(el("span", "kv-val mono", v));
      evKv.appendChild(row);
    });
    evCard.appendChild(evKv);

    if (Array.isArray(ev.limitations) && ev.limitations.length > 0) {
      const limTitle = el("div", "kv-key", "Inspection Scope Limitations");
      limTitle.style.marginTop = "14px";
      evCard.appendChild(limTitle);
      const ul = el("ul", "bullet-list");
      ev.limitations.forEach((lim) => {
        ul.appendChild(el("li", "", lim));
      });
      evCard.appendChild(ul);
    }

    grid.appendChild(evCard);
    stage.appendChild(grid);
  }

  async function runProfileAction(name, action, payload) {
    if (appState.busy) return;
    appState.busy = true;
    try {
      await apiFetch("/api/profiles/" + encodeURIComponent(name) + "/" + action, {
        method: "POST",
        body: payload || {},
      });
      showToast("Completed '" + action + "' on " + name + ".", "success");
      await refreshAll(name);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      appState.busy = false;
    }
  }

  async function deleteProfile(name) {
    if (appState.busy) return;
    appState.busy = true;
    try {
      await apiFetch("/api/profiles/" + encodeURIComponent(name), {
        method: "DELETE",
        body: { force_stop: false },
      });
      appState.confirmDeleteName = null;
      showToast("Deleted profile " + name + ".", "success");
      await refreshAll(null);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      appState.busy = false;
    }
  }

  function renderObligationsView() {
    const container = document.getElementById("view-obligations");
    if (!container) return;
    clearNode(container);

    const data = appState.obligations;
    if (!data) {
      const card = el("div", "card empty-card");
      card.appendChild(el("p", "muted-text", "Loading security obligation verification ledger..."));
      container.appendChild(card);
      return;
    }

    const summary = data.summary || {};
    const headerCard = el("section", "card hero-card");
    const ident = el("div", "hero-identity");
    const badge = el("div", "hero-badge", (summary.closed || 0) + "/" + (summary.total || 0));
    badge.style.backgroundColor = summary.failed === 0 ? "#10B981" : "#EF4444";

    const titles = el("div", "hero-titles");
    titles.appendChild(el("h1", "", "Reconstruction Obligation Ledger"));
    const sub = el("div", "hero-subline");
    sub.appendChild(el("span", "mono", data.ledger_id || ""));
    sub.appendChild(
      el(
        "span",
        "pill " + (summary.failed === 0 ? "pill-green" : "pill-red"),
        summary.failed === 0 ? "All Closed" : summary.failed + " Failed"
      )
    );
    sub.appendChild(el("span", "mono", data.verified_at || ""));
    titles.appendChild(sub);
    ident.appendChild(badge);
    ident.appendChild(titles);

    const verifyBtn = el("button", "btn btn-primary", "Re-verify All");
    verifyBtn.type = "button";
    verifyBtn.addEventListener("click", () => loadObligations(true));

    headerCard.appendChild(ident);
    headerCard.appendChild(verifyBtn);
    container.appendChild(headerCard);

    const tableCard = el("section", "card table-scroll");
    const table = el("table", "data-table");
    const thead = el("thead");
    const hr = el("tr");
    ["Obligation", "Status", "Owner Module", "Cases Checked", "Verification Detail", "Evidence"].forEach((col) => {
      hr.appendChild(el("th", "", col));
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody");
    (data.items || []).forEach((item) => {
      const tr = el("tr");
      const nameCell = el("td");
      nameCell.appendChild(el("div", "mono", item.obligation_id));
      nameCell.appendChild(el("div", "muted-text", item.title));
      tr.appendChild(nameCell);

      const stCell = el("td");
      stCell.appendChild(
        el("span", "pill " + (item.status === "closed" ? "pill-green" : "pill-red"), item.status)
      );
      tr.appendChild(stCell);

      const modCell = el("td");
      modCell.appendChild(el("div", "mono", item.owner_module));
      modCell.appendChild(el("div", "muted-text mono", String(item.module_sha256 || "").slice(0, 12)));
      tr.appendChild(modCell);

      tr.appendChild(el("td", "mono", (item.cases_checked || []).join(", ")));
      tr.appendChild(el("td", "", item.detail || ""));
      tr.appendChild(el("td", "mono", item.evidence_id || ""));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    tableCard.appendChild(table);
    container.appendChild(tableCard);
  }

  function renderDoctorView() {
    const container = document.getElementById("view-doctor");
    if (!container) return;
    clearNode(container);

    const data = appState.doctor;
    if (!data) {
      const card = el("div", "card empty-card");
      card.appendChild(el("p", "muted-text", "Running host diagnostics..."));
      container.appendChild(card);
      return;
    }

    const headCard = el("section", "card hero-card");
    const titles = el("div", "hero-titles");
    titles.appendChild(el("h1", "", "System Doctor Diagnostics"));
    titles.appendChild(el("p", "muted-text", (data.evidence && data.evidence.summary) || ""));

    const refreshBtn = el("button", "btn btn-primary", "Refresh Diagnostics");
    refreshBtn.type = "button";
    refreshBtn.addEventListener("click", () => loadDoctor(true));
    headCard.appendChild(titles);
    headCard.appendChild(refreshBtn);
    container.appendChild(headCard);

    const targetsGrid = el("section", "two-col-grid");
    const targets = data.targets || {};
    ["hub", "ide"].forEach((key) => {
      const t = targets[key] || {};
      const tc = el("div", "card");
      const row = el("div", "card-title-row");
      row.appendChild(el("h2", "", key === "hub" ? "Antigravity Hub" : "Antigravity IDE"));
      row.appendChild(
        el(
          "span",
          "pill " + (t.installed ? "pill-green" : "pill-amber"),
          t.installed ? "Installed" : "Not Installed"
        )
      );
      tc.appendChild(row);
      const kv = el("div", "kv-table");
      [
        ["App Path", t.app_path || ""],
        ["Executable", t.executable_path || "missing"],
        ["Version", t.version || "unknown"],
        ["Bundle ID", t.bundle_id || "unknown"],
      ].forEach(([k, v]) => {
        const kr = el("div", "kv-row");
        kr.appendChild(el("span", "kv-key", k));
        kr.appendChild(el("span", "kv-val mono", v));
        kv.appendChild(kr);
      });
      tc.appendChild(kv);
      targetsGrid.appendChild(tc);
    });
    container.appendChild(targetsGrid);

    const checksCard = el("section", "card table-scroll");
    const table = el("table", "data-table");
    const thead = el("thead");
    const hr = el("tr");
    ["Check", "Status", "Details"].forEach((c) => hr.appendChild(el("th", "", c)));
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody");
    (data.checks || []).forEach((chk) => {
      const tr = el("tr");
      tr.appendChild(el("td", "mono", chk.id));
      const pillCls =
        chk.status === "pass"
          ? "pill-green"
          : chk.status === "fail"
          ? "pill-red"
          : chk.status === "warn"
          ? "pill-amber"
          : "pill-blue";
      const stTd = el("td");
      stTd.appendChild(el("span", "pill " + pillCls, chk.status));
      tr.appendChild(stTd);
      tr.appendChild(el("td", "mono", chk.detail || ""));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    checksCard.appendChild(table);
    container.appendChild(checksCard);
  }

  async function loadObligations(showMessage) {
    try {
      appState.obligations = await apiFetch("/api/obligations");
      renderObligationsView();
      if (showMessage) {
        showToast("Obligation checks completed.", "success");
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  async function loadDoctor(showMessage) {
    try {
      appState.doctor = await apiFetch("/api/doctor");
      renderDoctorView();
      if (showMessage) {
        showToast("Host diagnostics updated.", "success");
      }
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  function switchView(viewName) {
    appState.view = viewName;
    document.querySelectorAll(".nav-tab").forEach((tab) => {
      tab.classList.toggle("is-active", tab.getAttribute("data-view") === viewName);
    });
    document.getElementById("view-profiles").classList.toggle("is-hidden", viewName !== "profiles");
    document.getElementById("view-obligations").classList.toggle("is-hidden", viewName !== "obligations");
    document.getElementById("view-doctor").classList.toggle("is-hidden", viewName !== "doctor");

    if (viewName === "obligations" && !appState.obligations) {
      loadObligations(false);
    }
    if (viewName === "doctor" && !appState.doctor) {
      loadDoctor(false);
    }
  }

  async function refreshAll(preferredName) {
    try {
      const overview = await apiFetch("/api/state");
      appState.overview = overview;
      renderHeaderMeta();

      const names = (overview.profiles || []).map((p) => p.manifest && p.manifest.name).filter(Boolean);
      let nextSelected = preferredName !== undefined ? preferredName : appState.selectedName;
      if (!nextSelected || names.indexOf(nextSelected) === -1) {
        nextSelected = names.length > 0 ? names[0] : null;
      }
      await selectProfile(nextSelected);
    } catch (err) {
      showToast(err.message, "error");
    }
  }

  function wireEvents() {
    document.querySelectorAll(".nav-tab").forEach((tab) => {
      tab.addEventListener("click", () => switchView(tab.getAttribute("data-view")));
    });

    const searchInput = document.getElementById("profile-search");
    if (searchInput) {
      searchInput.addEventListener("input", () => {
        appState.query = searchInput.value;
        renderSidebar();
      });
    }

    document.querySelectorAll(".filter-chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        appState.filter = chip.getAttribute("data-filter") || "all";
        document.querySelectorAll(".filter-chip").forEach((c) => {
          c.classList.toggle("is-active", c === chip);
        });
        renderSidebar();
      });
    });

    const openCreate = document.getElementById("open-create-btn");
    if (openCreate) {
      openCreate.addEventListener("click", () => openDrawer("create-drawer"));
    }

    const backdrop = document.getElementById("drawer-backdrop");
    if (backdrop) {
      backdrop.addEventListener("click", closeAllDrawers);
    }

    document.querySelectorAll("[data-close-drawer]").forEach((btn) => {
      btn.addEventListener("click", closeAllDrawers);
    });

    const createForm = document.getElementById("create-form");
    if (createForm) {
      createForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(createForm);
        const payload = {
          name: String(formData.get("name") || "").trim(),
          label: String(formData.get("label") || "").trim() || undefined,
          accent: String(formData.get("accent") || "#3B82F6"),
          default_target: String(formData.get("default_target") || "hub"),
          link_policy: String(formData.get("link_policy") || "minimal"),
          auth_mode: String(formData.get("auth_mode") || "isolated-file"),
          inherit_config: Boolean(document.getElementById("create-inherit").checked),
          keep_background_alive: Boolean(document.getElementById("create-keep-bg").checked),
        };
        try {
          const created = await apiFetch("/api/profiles", { method: "POST", body: payload });
          createForm.reset();
          buildAccentPicker();
          closeAllDrawers();
          showToast("Created sandbox profile " + payload.name + ".", "success");
          await refreshAll(created.manifest ? created.manifest.name : payload.name);
        } catch (err) {
          showToast(err.message, "error");
        }
      });
    }

    const cloneForm = document.getElementById("clone-form");
    if (cloneForm) {
      cloneForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const source = String(document.getElementById("clone-source").value || "");
        const target = String(document.getElementById("clone-target").value || "").trim();
        const label = String(document.getElementById("clone-label").value || "").trim();
        try {
          await apiFetch("/api/profiles/" + encodeURIComponent(source) + "/clone", {
            method: "POST",
            body: { target, label: label || undefined },
          });
          cloneForm.reset();
          closeAllDrawers();
          showToast("Cloned " + source + " to " + target + ".", "success");
          await refreshAll(target);
        } catch (err) {
          showToast(err.message, "error");
        }
      });
    }

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        closeAllDrawers();
      } else if (e.key === "/" && document.activeElement && document.activeElement.tagName !== "INPUT") {
        e.preventDefault();
        if (searchInput) searchInput.focus();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    stripBootstrapTokenFromUrl();
    initTheme();
    buildAccentPicker();
    wireEvents();
    refreshAll();
  });
})();
