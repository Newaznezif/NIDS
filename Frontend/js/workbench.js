/* Cybersecurity Analyst Workbench client.
   Every rendered value comes from a /api/wb/* response; provenance labels are
   shown as pills so fact vs interpretation vs external intel is always visible. */
(function () {
  const $ = (id) => document.getElementById(id);

  const PILL = {
    OBSERVED: "obs", CALCULATED: "calc", EXTRACTED: "calc",
    "EXTERNAL INTELLIGENCE": "ext", INFERRED: "ext",
    "USER-PROVIDED": "user", UNAVAILABLE: "unav", "DEMO DATA": "demo",
  };
  const pill = (p) => `<span class="pill ${PILL[p] || "unav"}">${esc(p || "UNAVAILABLE")}</span>`;
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({
      headers: { "Accept": "application/json" },
    }, opts));
    if (res.status === 401) { location.href = "/login"; throw new Error("auth"); }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }
  const post = (path, body) => api(path, {
    method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(body || {}),
  });

  /* ---- session / nav ---- */
  async function boot() {
    const s = await api("/api/wb/session");
    if (!s.authenticated) { location.href = "/login"; return; }
    $("wb-user").textContent = "signed in as " + s.user;
    document.querySelectorAll(".wb-nav button").forEach((b) => {
      b.onclick = () => {
        document.querySelectorAll(".wb-nav button").forEach((x) => x.classList.remove("active"));
        document.querySelectorAll(".view").forEach((x) => x.classList.remove("active"));
        b.classList.add("active");
        $("view-" + b.dataset.view).classList.add("active");
        loadView(b.dataset.view);
      };
    });
    $("wb-logout").onclick = async () => { await post("/api/wb/logout"); location.href = "/login"; };
    loadView("dashboard");
  }

  function loadView(v) {
    ({ dashboard: renderDashboard, investigate: renderInvestigate, logs: renderLogs,
       files: renderFiles, cases: renderCases, reports: renderReports,
       providers: renderProviders, demo: renderDemo }[v] || (() => {}))();
  }

  /* ---- generic renderers ---- */
  function renderValue(obj, indent) {
    if (obj && typeof obj === "object" && "provenance" in obj && "value" in obj) {
      return `<b>${esc(obj.value)}</b> ${pill(obj.provenance)}${obj.source ? ` <span class="muted">${esc(obj.source)}</span>` : ""}`;
    }
    if (Array.isArray(obj)) {
      return obj.length ? "<ul>" + obj.map((i) => `<li>${renderValue(i, indent + 1)}</li>`).join("") + "</ul>" : "<span class='muted'>none</span>";
    }
    if (obj && typeof obj === "object") {
      return "<div class='kv'>" + Object.entries(obj).map(([k, v]) =>
        `<div><b>${esc(k)}:</b> ${renderValue(v, indent + 1)}</div>`).join("") + "</div>";
    }
    return esc(obj);
  }

  function table(headers, rows) {
    if (!rows.length) return "<div class='muted'>No records.</div>";
    return "<table><thead><tr>" + headers.map((h) => `<th>${h}</th>`).join("") +
      "</tr></thead><tbody>" + rows.map((r) => "<tr>" + r.map((c) => `<td>${c}</td>`).join("") + "</tr>").join("") +
      "</tbody></table>";
  }

  /* ---- dashboard ---- */
  async function renderDashboard() {
    const d = await api("/api/wb/dashboard");
    const cards = [
      ["Active cases", d.active_cases.length],
      ["Recent investigations", d.recent_investigations.length],
      ["Recent reports", d.recent_reports.length],
      ["NIDS total alerts", d.nids.total_alerts],
    ];
    let html = "<div class='grid'>" + cards.map(([k, v]) =>
      `<div class='card'><div class='muted'>${k}</div><div style='font-size:22px;font-family:var(--font-mono)'>${v}</div></div>`).join("") + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Active investigations</h2>" +
      table(["Case", "Title", "Status", "Priority", "Analyst"],
        d.active_cases.map((c) => [esc(c.case_id), esc(c.title), esc(c.status), esc(c.priority), esc(c.analyst)])) + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Recent investigations</h2>" +
      table(["Type", "Indicator", "When"], d.recent_investigations.map((i) =>
        [esc(i.ioc_type), esc(i.ioc_value), esc(i.created_at)])) + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Intel provider status</h2>" +
      table(["Provider", "Status", "Supports"], d.providers.map((p) =>
        [esc(p.provider), pill(p.status === "CONFIGURED" ? "EXTERNAL INTELLIGENCE" : "UNAVAILABLE") + " " + esc(p.status), esc((p.supports || []).join(", "))])) + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Analysis activity (audit)</h2>" +
      table(["When", "User", "Event", "Detail"], d.analysis_activity.map((a) =>
        [esc(a.ts), esc(a.username), esc(a.event), esc(a.detail)])) + "</div>";
    $("dash-content").innerHTML = html;
  }

  /* ---- investigate ---- */
  function renderInvestigate() {
    $("ioc-run").onclick = async () => {
      $("ioc-err").textContent = ""; $("ioc-result").innerHTML = "";
      const value = $("ioc-input").value.trim();
      try {
        const r = await post("/api/wb/investigate", { value });
        $("ioc-type").innerHTML = "Detected type: <b>" + esc(r.detected_type) + "</b> " + pill("CALCULATED");
        $("ioc-result").innerHTML = renderResult(r.result, r.investigation_id);
        renderInvestigateRecent();
      } catch (e) { $("ioc-err").textContent = e.message; }
    };
    renderInvestigateRecent();
  }

  function renderResult(res, invId) {
    let html = `<div class='card'><div class='row'><span class='muted'>Investigation #${invId}</span>
      <button class='secondary attach' data-inv='${invId}' data-val='${esc(res.indicator)}' data-type='${esc(res.indicator_type)}'>Attach to case</button></div>`;
    for (const [section, val] of Object.entries(res)) {
      if (section === "indicator" || section === "indicator_type") continue;
      if (section === "threat_intelligence") {
        html += "<h2 style='font-size:13px;margin-top:12px'>Threat intelligence</h2>";
        html += (val || []).map((t) => `<div class='kv'><b>${esc(t.provider)}</b> ${pill(t.provenance)}
          status=${esc(t.status)} retrieved=${esc(t.retrieved_at)}
          ${t.reason ? `<span class='muted'>(${esc(t.reason)})</span>` : ""}
          ${t.data && Object.keys(t.data).length ? renderValue(t.data, 0) : ""}</div>`).join("") ||
          "<div class='muted'>No intelligence returned. This does not mean the indicator is safe.</div>";
        continue;
      }
      if (val == null) continue;
      html += `<h2 style='font-size:13px;margin-top:12px'>${esc(section)}</h2>` + renderValue(val, 0);
    }
    html += "</div>";
    setTimeout(bindAttach, 0);
    return html;
  }

  let pendingAttach = null;
  function bindAttach() {
    document.querySelectorAll("button.attach").forEach((b) => {
      b.onclick = async () => {
        const cases = await api("/api/wb/cases");
        if (!cases.cases.length) { alert("Create a case first."); return; }
        const pick = prompt("Attach to case db id? (" + cases.cases.map((c) => c.id + "=" + c.case_id).join(", ") + ")");
        if (!pick) return;
        await post(`/api/wb/cases/${pick}/items`, {
          item_type: b.dataset.type === "IPv4" || b.dataset.type === "IPv6" ? "ip"
            : b.dataset.type.toLowerCase(),
          item_ref: b.dataset.val,
          provenance: "OBSERVED",
        });
        alert("Attached.");
      };
    });
  }

  async function renderInvestigateRecent() {
    const r = await api("/api/wb/investigations");
    $("ioc-recent").innerHTML = table(["#", "Type", "Indicator", "When", "Analyst"],
      r.investigations.map((i) => [i.id, esc(i.ioc_type), esc(i.ioc_value), esc(i.created_at), esc(i.analyst)]));
  }

  /* ---- logs ---- */
  function renderLogs() {
    $("log-upload").onclick = async () => {
      $("log-err").textContent = ""; $("log-result").innerHTML = "";
      const f = $("log-file").files[0];
      if (!f) { $("log-err").textContent = "Choose a file first."; return; }
      const fd = new FormData(); fd.append("file", f);
      try {
        const r = await api("/api/wb/logs", { method: "POST", body: fd });
        $("log-result").innerHTML = renderLogSummary(r.log_id, r.summary, f.name);
      } catch (e) { $("log-err").textContent = e.message; }
    };
  }

  function renderLogSummary(lid, s, name) {
    const ov = s.overview, st = s.statistics;
    let html = `<div class='card'><h2 style='font-size:13px'>${esc(name)} — overview ${pill(ov.provenance)}</h2>
      <div class='kv'>${Object.entries(ov).filter(([k]) => k !== "provenance" && k !== "source")
        .map(([k, v]) => `<div><b>${esc(k)}:</b> ${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`).join("")}</div></div>`;
    html += "<div class='card'><h2 style='font-size:13px'>Statistics</h2><div class='grid'>" +
      [["top source IPs", st.top_source_ips], ["top destination IPs", st.top_destination_ips],
       ["top domains", st.top_domains], ["top URLs", st.top_urls],
       ["HTTP status", st.http_status_codes], ["event types", Object.entries(st.event_types)]]
        .map(([k, v]) => `<div><div class='muted'>${k}</div><div class='kv'>${
          (v || []).map((x) => esc(Array.isArray(x) ? x.join(" : ") : x)).join("<br>") || "none"}</div></div>`).join("") +
      "</div></div>";
    html += `<div class='card'><h2 style='font-size:13px'>Extracted IOCs ${pill("EXTRACTED")}</h2>` +
      table(["Type", "Value", "Occurrences"], s.iocs.slice(0, 60).map((i) =>
        [esc(i.type), esc(i.value), i.occurrences])) + "</div>";
    html += `<div class='card'><h2 style='font-size:13px'>Search</h2>
      <div class='row'><input id='ls-q' placeholder='keyword'><input id='ls-regex' placeholder='regex'>
      <input id='ls-ip' placeholder='ip'><select id='ls-sev'><option value=''>severity</option><option>INFO</option><option>WARNING</option><option>ERROR</option></select>
      <button class='primary' id='ls-run'>Search</button></div>
      <div id='ls-out' style='margin-top:10px'></div></div>`;
    setTimeout(() => {
      $("ls-run").onclick = async () => {
        const r = await post(`/api/wb/logs/${lid}/search`, {
          keyword: $("ls-q").value || null, regex: $("ls-regex").value || null,
          ip: $("ls-ip").value || null, severity: $("ls-sev").value || null,
        });
        $("ls-out").innerHTML = r.error ? `<div class='err'>${esc(r.error)}</div>` :
          table(["Line", "Severity", "Type", "Text"], r.matches.map((m) =>
            [m.line, esc(m.severity), esc(m.event_type), esc(m.text)]));
      };
    }, 0);
    return html;
  }

  /* ---- files ---- */
  function renderFiles() {
    $("file-upload").onclick = async () => {
      $("file-err").textContent = ""; $("file-result").innerHTML = "";
      const f = $("file-input").files[0];
      if (!f) { $("file-err").textContent = "Choose a file first."; return; }
      const fd = new FormData(); fd.append("file", f);
      try {
        const r = await api("/api/wb/files", { method: "POST", body: fd });
        const a = r.analysis;
        $("file-result").innerHTML = `<div class='card'><h2 style='font-size:13px'>${esc(a.original_name)}
          (${esc(a.kind)}, ${a.size} bytes)</h2>
          <div class='kv'>
            <div><b>md5:</b> ${esc(a.md5)} ${pill("CALCULATED")}<button class='copy' data-c='${esc(a.md5)}'>copy</button></div>
            <div><b>sha1:</b> ${esc(a.sha1)} ${pill("CALCULATED")}</div>
            <div><b>sha256:</b> ${esc(a.sha256)} ${pill("CALCULATED")}<button class='copy' data-c='${esc(a.sha256)}'>copy</button></div>
            <div><b>sha512:</b> ${esc(a.sha512)} ${pill("CALCULATED")}</div>
            <div><b>entropy:</b> ${a.entropy} ${pill("CALCULATED")}</div>
            <div><b>external submission:</b> ${esc(a.external_submission)} ${pill("UNAVAILABLE")}</div>
          </div>
          <h2 style='font-size:13px;margin-top:12px'>Structure</h2>${renderValue(a.structure, 0)}
          <h2 style='font-size:13px;margin-top:12px'>Strings (extracted)</h2>
          <pre>${esc((a.strings || []).slice(0, 80).join("\n")) || "none"}</pre></div>`;
        document.querySelectorAll("button.copy").forEach((b) => b.onclick = () =>
          navigator.clipboard.writeText(b.dataset.c));
      } catch (e) { $("file-err").textContent = e.message; }
    };
  }

  /* ---- encode ---- */
  document.addEventListener("DOMContentLoaded", () => {
    $("enc-run").onclick = async () => {
      $("enc-err").textContent = "";
      try {
        const r = await post("/api/wb/encode", {
          operation: $("enc-op").value, codec: $("enc-codec").value, data: $("enc-input").value,
        });
        $("enc-output").textContent = JSON.stringify(r.output, null, 2);
      } catch (e) { $("enc-err").textContent = e.message; $("enc-output").textContent = ""; }
    };
    $("enc-copy").onclick = () => navigator.clipboard.writeText($("enc-output").textContent);

    $("cidr-run").onclick = async () => {
      const r = await post("/api/wb/network/cidr", { cidr: $("cidr-input").value });
      $("cidr-out").textContent = JSON.stringify(r, null, 2);
    };
    $("dns-run").onclick = async () => {
      const r = await post("/api/wb/network/dns", { name: $("dns-name").value, qtype: $("dns-type").value });
      $("dns-out").textContent = JSON.stringify(r, null, 2);
    };
    $("rdns-run").onclick = async () => {
      try {
        const r = await post("/api/wb/network/rdns", { ip: $("rdns-ip").value });
        $("dns-out").textContent = JSON.stringify(r, null, 2);
      } catch (e) { $("dns-out").textContent = e.message; }
    };
  });

  /* ---- cases ---- */
  async function renderCases() {
    $("case-create").onclick = async () => {
      $("case-err").textContent = "";
      try {
        await post("/api/wb/cases", {
          title: $("case-title").value, description: $("case-desc").value,
          priority: $("case-priority").value,
        });
        $("case-title").value = ""; $("case-desc").value = "";
        renderCases();
      } catch (e) { $("case-err").textContent = e.message; }
    };
    const r = await api("/api/wb/cases");
    $("case-list").innerHTML = "<div class='card'>" +
      table(["Case", "Title", "Status", "Priority", "Analyst", ""], r.cases.map((c) =>
        [esc(c.case_id), esc(c.title), esc(c.status), esc(c.priority), esc(c.analyst),
         `<button class='secondary open' data-id='${c.id}'>Open</button>`])) + "</div>";
    document.querySelectorAll("button.open").forEach((b) => b.onclick = () => openCase(+b.dataset.id));
  }

  async function openCase(id) {
    const d = await api(`/api/wb/cases/${id}`);
    const c = d.case;
    let html = `<div class='card'><h2 style='font-size:14px'>${esc(c.case_id)} — ${esc(c.title)}</h2>
      <div class='kv'><div><b>status:</b> ${esc(c.status)} <b>priority:</b> ${esc(c.priority)}
      <b>analyst:</b> ${esc(c.analyst)} <b>created:</b> ${esc(c.created_at)}</div>
      <div>${esc(c.description)}</div></div>
      <div class='row' style='margin-top:10px'>
        <select id='cd-status'><option>OPEN</option><option>IN_PROGRESS</option><option>RESOLVED</option><option>CLOSED</option></select>
        <button class='secondary' id='cd-setstatus'>Set status</button>
        <select id='cd-fmt'><option value='pdf'>PDF</option><option value='json'>JSON</option><option value='csv'>CSV</option></select>
        <button class='primary' id='cd-report'>Generate report</button>
      </div>
      <div class='row' style='margin-top:10px'>
        <select id='cd-itype'><option>ip</option><option>url</option><option>domain</option><option>hash</option><option>ioc</option><option>alert</option><option>file</option><option>log</option><option>investigation</option></select>
        <input id='cd-iref' placeholder='value / id'>
        <button class='secondary' id='cd-additem'>Attach evidence</button>
      </div>
      <textarea id='cd-note' style='margin-top:10px' placeholder='Analyst note (interpretation)'></textarea>
      <div class='row'><button class='secondary' id='cd-addnote'>Add note</button></div>
      <div class='err' id='cd-err'></div></div>`;
    html += "<div class='card'><h2 style='font-size:13px'>Evidence items</h2>" +
      table(["Type", "Ref", "Label", "Provenance", "Added"], d.items.map((i) =>
        [esc(i.item_type), esc(i.item_ref), esc(i.label), pill(i.provenance), esc(i.added_at)])) + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Timeline</h2>" +
      table(["When", "Kind", "Summary", "Provenance"], d.timeline.map((t) =>
        [esc(t.ts), esc(t.kind), esc(t.summary), pill(t.provenance)])) + "</div>";
    html += "<div class='card'><h2 style='font-size:13px'>Analyst notes</h2>" +
      d.notes.map((n) => `<div class='kv'><b>${esc(n.created_at)} ${esc(n.author)}</b> ${pill("USER-PROVIDED")}<div>${esc(n.body)}</div></div>`).join("") ||
      "<div class='muted'>No notes.</div>" + "</div>";
    $("case-detail").innerHTML = html;

    $("cd-setstatus").onclick = async () => {
      await post(`/api/wb/cases/${id}/status`, { status: $("cd-status").value }); openCase(id);
    };
    $("cd-report").onclick = async () => {
      try {
        const r = await post(`/api/wb/cases/${id}/report`, { format: $("cd-fmt").value });
        window.location.href = r.download_url;
        openCase(id);
      } catch (e) { $("cd-err").textContent = e.message; }
    };
    $("cd-additem").onclick = async () => {
      try {
        await post(`/api/wb/cases/${id}/items`, {
          item_type: $("cd-itype").value, item_ref: $("cd-iref").value, provenance: "USER-PROVIDED",
        });
        openCase(id);
      } catch (e) { $("cd-err").textContent = e.message; }
    };
    $("cd-addnote").onclick = async () => {
      try { await post(`/api/wb/cases/${id}/notes`, { body: $("cd-note").value }); openCase(id); }
      catch (e) { $("cd-err").textContent = e.message; }
    };
  }

  /* ---- reports ---- */
  async function renderReports() {
    const r = await api("/api/wb/reports");
    $("report-list").innerHTML = "<div class='card'>" +
      table(["#", "Format", "File", "When", "Analyst", ""], r.reports.map((x) =>
        [x.id, esc(x.fmt), esc(x.stored_name), esc(x.created_at), esc(x.analyst),
         `<a href='/api/wb/reports/download/${esc(x.stored_name)}'>download</a>`])) + "</div>";
  }

  /* ---- providers ---- */
  async function renderProviders() {
    const r = await api("/api/wb/providers");
    $("provider-list").innerHTML = "<div class='card'>" +
      table(["Provider", "Status", "Supports"], r.providers.map((p) =>
        [esc(p.provider), esc(p.status), esc((p.supports || []).join(", "))])) +
      "<div class='muted' style='margin-top:10px'>Keys are read from environment variables only and are never exposed to the frontend.</div></div>";
  }

  /* ---- demo ---- */
  async function renderDemo() {
    $("demo-seed").onclick = async () => {
      const r = await post("/api/wb/demo/seed");
      $("demo-msg").textContent = r.enabled ? ("Demo case " + (r.case_id || "") + (r.created ? " created." : " already present.")) : "Demo disabled.";
      renderDemo();
    };
    const b = await api("/api/wb/demo");
    const cases = await api("/api/wb/demo/cases");
    $("demo-content").innerHTML =
      `<div class='card'>${pill("DEMO DATA")} <span class='muted'>${esc(b.note)}</span></div>` +
      "<div class='card'><h2 style='font-size:13px'>Demo cases</h2>" +
      table(["Case", "Title", "Status"], cases.cases.map((c) => [esc(c.case_id), esc(c.title), esc(c.status)])) + "</div>" +
      "<div class='card'><h2 style='font-size:13px'>Sample IOCs</h2>" +
      table(["Type", "Value"], b.sample_iocs.map((i) => [esc(i.type), esc(i.value)])) + "</div>" +
      "<div class='card'><h2 style='font-size:13px'>Sample log</h2><pre>" + esc(b.sample_log) + "</pre></div>";
  }

  boot();
})();
