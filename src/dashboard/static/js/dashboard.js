/* PacketGuard dashboard — polls the engine and renders the live view.
   No framework: small, explicit DOM updates on a ~1.2s cadence. */

(() => {
  "use strict";

  const POLL_MS = 1200;
  const SPARK_LEN = 44;
  const FEED_MAX = 40;

  const RULES = {
    R001: { name: "Packet loss / theft", sev: "HIGH" },
    R002: { name: "Tampering",           sev: "HIGH" },
    R003: { name: "Replay attack",       sev: "MEDIUM" },
    R004: { name: "DoS / flood",         sev: "HIGH" },
    R005: { name: "Spam activity",       sev: "MEDIUM" },
    R006: { name: "Data exfiltration",   sev: "MEDIUM" },
    R007: { name: "Route hijack",        sev: "MEDIUM" },
    R008: { name: "MitM / ARP spoof",    sev: "HIGH" },
  };

  // Which rules the blockchain ledger catches vs. standard network hygiene.
  const CLASS = { R001: "ledger", R002: "ledger", R003: "ledger", R007: "ledger",
                  R004: "hygiene", R005: "hygiene", R006: "hygiene", R008: "hygiene" };

  const SCENARIO_LABELS = {
    tampering: "Tampering", packet_drop: "Packet drop", replay: "Replay",
    syn_flood: "SYN flood", spam: "Spam", exfil: "Exfiltration",
    dns_tunnel: "DNS tunnel", route_hijack: "Route hijack", arp_spoof: "ARP spoof",
  };

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });

  let sparkData = [];
  let lastProcessed = null;
  const REDUCED = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const DL_ICON = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2.5v6.5m0 0 2.6-2.6M8 9 5.4 6.4" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M3.5 12.3h9" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';

  /* Build a DOM node from an HTML string (single root element). */
  function nodeFromHTML(html) {
    const t = document.createElement("template");
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  }

  /* Keyed list sync: reuse existing nodes by key (no re-animation), create new
     ones with an entrance, drop removed ones. Keeps the live feed from flickering. */
  function syncList(container, items, keyFn, renderHTML, emptyMsg) {
    if (!items.length) { container.innerHTML = `<div class="empty">${emptyMsg}</div>`; return; }
    const existing = new Map();
    for (const el of Array.from(container.children)) {
      if (el.dataset && el.dataset.key) existing.set(el.dataset.key, el);
    }
    const ordered = [];
    for (const item of items) {
      const key = String(keyFn(item));
      let el = existing.get(key);
      if (el) { existing.delete(key); }
      else {
        el = nodeFromHTML(renderHTML(item));
        if (el) {
          el.dataset.key = key;
          if (!REDUCED) {
            el.classList.add("enter");
            el.addEventListener("animationend", () => el.classList.remove("enter"), { once: true });
          }
        }
      }
      if (el) ordered.push(el);
    }
    container.replaceChildren(...ordered);
  }

  /* Animated count-up for the stat tiles (ease-out, ~0.55s). */
  const lastNum = {};
  function setNum(id, value) {
    const el = $(id);
    if (!el) return;
    const from = lastNum[id];
    lastNum[id] = value;
    if (REDUCED || from == null || from === value) { el.textContent = value.toLocaleString(); return; }
    const start = performance.now(), dur = 550, delta = value - from;
    function tick(now) {
      const t = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(from + delta * eased).toLocaleString();
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  /* ----------------------------------------------------------- Theme & demo */
  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("pg-theme"); } catch (_) {}
    if (saved) document.documentElement.setAttribute("data-theme", saved);
    $("themeToggle").addEventListener("click", () => {
      const cur = document.documentElement.getAttribute("data-theme");
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      const next = cur ? (cur === "dark" ? "light" : "dark")
                       : (prefersDark ? "light" : "dark");
      document.documentElement.setAttribute("data-theme", next);
      try { localStorage.setItem("pg-theme", next); } catch (_) {}
    });
  }

  function initDemoToggle() {
    $("demoToggle").addEventListener("click", async () => {
      const btn = $("demoToggle");
      const turningOn = btn.getAttribute("aria-pressed") !== "true";
      try {
        const r = await fetch("/api/demo", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ running: turningOn }),
        });
        const data = await r.json();
        setDemoState(data.running);
      } catch (_) {}
    });
  }

  function setDemoState(running) {
    const btn = $("demoToggle");
    btn.setAttribute("aria-pressed", String(running));
    btn.textContent = "Demo: " + (running ? "on" : "off");
  }

  let toastTimer = null;
  function toast(html, kind) {
    const el = $("toast");
    el.className = "toast" + (kind && kind !== "ok" ? " toast--" + kind : "");
    el.innerHTML = `<span class="toast__dot"></span><span>${html}</span>`;
    el.hidden = false;
    requestAnimationFrame(() => el.classList.add("show"));
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
      el.classList.remove("show");
      setTimeout(() => { el.hidden = true; }, 240);
    }, 3600);
  }

  function initInject() {
    document.querySelectorAll(".chip").forEach((chip) => {
      chip.addEventListener("click", async () => {
        chip.classList.remove("flash");
        void chip.offsetWidth;            // restart the animation
        chip.classList.add("flash");
        const label = SCENARIO_LABELS[chip.dataset.scenario] || "Attack";
        try {
          const r = await fetch("/api/inject", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scenario: chip.dataset.scenario }),
          });
          const d = await r.json();
          if (d && d.fired && d.fired.length) {
            const rules = [...new Set(d.fired)].sort().join(" ");
            toast(`<b>${esc(label)}</b> injected &rarr; <code>${esc(rules)}</code> caught`, "ok");
          } else {
            toast(`<b>${esc(label)}</b> injected — already alerting (suppressed)`, "warn");
          }
        } catch (_) { toast(`<b>${esc(label)}</b> — request failed`, "crit"); }
        refresh();                        // pull the result immediately
      });
    });
  }

  /* --------------------------------------------------------------- Renderers */
  function renderStats(s) {
    const st = s.stats, bc = s.blockchain;
    setNum("statProcessed", st.processed);
    $("statThroughput").textContent = st.throughput_pps.toFixed(1) + " pkt/s";
    setNum("statVerified", st.verified);
    const pct = st.anchored ? Math.round((st.verified / st.anchored) * 100) : 0;
    $("statVerifiedPct").textContent = pct + "% of " + st.anchored.toLocaleString() + " anchored";
    setNum("statFlagged", st.flagged);
    setNum("statBlocks", bc.length);
    $("statDifficulty").textContent = "PoW difficulty " + bc.difficulty;
    $("statUptime").textContent = "uptime " + fmtUptime(st.uptime_seconds);
  }

  function fmtUptime(sec) {
    sec = Math.floor(sec);
    if (sec < 60) return sec + "s";
    const m = Math.floor(sec / 60), s = sec % 60;
    if (m < 60) return m + "m " + s + "s";
    return Math.floor(m / 60) + "h " + (m % 60) + "m";
  }

  function renderPills(s, health) {
    const chain = s.blockchain;
    const cp = $("chainPill"), hp = $("healthPill");
    cp.className = "pill " + (chain.valid ? "pill--ok" : "pill--crit");
    $("chainPillText").textContent = chain.valid ? "Chain intact" : "Chain broken";
    const bs = chain.batch_size || 1;
    $("chainStatus").textContent = chain.status + (bs > 1 ? ` · ${bs}/block` : "");
    renderQuorum(chain.quorum);
    const healthy = health && health.status === "healthy";
    hp.className = "pill " + (healthy ? "pill--ok" : "pill--crit");
    $("healthPillText").textContent = healthy ? "Healthy" : "Degraded";
    if (health) {
      setDemoState(health.demo_running);
      $("statSuppressed").textContent = health.suppressed_alerts.toLocaleString() + " suppressed";
    }
  }

  function renderQuorum(q) {
    const pill = $("quorumPill");
    if (!q) {
      pill.className = "pill";
      $("quorumPillText").textContent = "Single chain";
      $("quorum").innerHTML = `<p class="empty">Running on a single ledger (no quorum).</p>`;
      return;
    }
    const intact = q.witnesses.filter((w) => w.valid).length;
    pill.className = "pill " + (q.healthy ? "pill--ok" : "pill--crit");
    $("quorumPillText").textContent = `Quorum ${intact}/${q.nodes}`;
    $("quorumScheme").textContent = `${q.threshold}-of-${q.nodes}`;
    $("quorumDetail").textContent = q.detail;
    $("quorum").innerHTML = q.witnesses.map((w) => `
      <div class="witness ${w.valid ? "" : "witness--bad"}">
        <span class="witness__dot"></span>
        <span class="witness__name">${esc(w.name)}</span>
        <span class="witness__meta">${w.blocks} blocks</span>
        <span class="witness__state">${w.valid ? "intact" : "compromised"}</span>
      </div>`).join("");
  }

  function renderProof(p) {
    const el = $("proofOut");
    const merkleOk = p.merkle.self_check;
    const q = p.quorum;
    const votes = q ? Object.entries(q.per_witness).map(([n, s]) =>
      `<span class="vote vote--${s === "verified" ? "ok" : "bad"}">${esc(n)}: ${esc(s)}</span>`).join("") : "";
    el.innerHTML = `
      <div class="proof__verdict proof__verdict--${p.verification === "verified" ? "ok" : "bad"}">
        ${p.verification === "verified" ? "✓ VERIFIED" : "✗ " + p.verification.toUpperCase()}
        <span>seq ${esc(p.seq)}</span>
      </div>
      <dl class="proof__grid">
        <dt>Anchored hash</dt><dd class="mono">${esc(p.anchored_hash.slice(0, 32))}…</dd>
        <dt>Merkle root</dt><dd class="mono">${esc(p.merkle.root.slice(0, 32))}…</dd>
        <dt>Merkle self-check</dt><dd>${merkleOk ? "✓ path valid" : "✗ invalid"} · ${p.merkle.path.length} hops</dd>
        <dt>Block</dt><dd>#${esc(p.block.index)} · ${esc(p.block.packets_in_block)} packets · ${esc(p.block.hash.slice(0, 20))}…</dd>
        <dt>Chain</dt><dd>${p.chain.valid ? "✓ " : "✗ "}${esc(p.chain.status)}</dd>
        ${q ? `<dt>Quorum ${esc(q.scheme)}</dt><dd>${q.confirmed ? "✓ confirmed" : "✗ not confirmed"} (${q.agree}/${Object.keys(q.per_witness).length}) <span class="votes">${votes}</span></dd>` : ""}
      </dl>`;
    const dl = $("proofDownload");
    dl.href = `/api/proof?seq=${p.seq}&download=1`;
    dl.hidden = false;
  }

  async function exportProof(seq) {
    if (seq === "" || seq == null || isNaN(seq)) {
      $("proofOut").innerHTML = `<p class="empty">Enter a packet sequence number — or click a verified/tampered row in the feed, or an alert's “proof” button.</p>`;
      return;
    }
    $("proofSeq").value = seq;
    try {
      const r = await fetch(`/api/proof?seq=${encodeURIComponent(seq)}`);
      if (!r.ok) { $("proofOut").innerHTML = `<p class="empty">No ledger record for seq ${esc(seq)}. Try a sequence number visible in the feed.</p>`; return; }
      renderProof(await r.json());
    } catch (_) {}
  }

  function feedRow(p) {
    const rules = (p.rules || []).map((r) => `<span class="badge">${esc(r)}</span>`).join("");
    // Only anchored packets (verified/tampered) have a ledger record to prove.
    const provable = p.status === "verified" || p.status === "tampered";
    const proofBtn = provable
      ? `<button class="row__proof" data-seq="${esc(p.seq)}" title="Export proof for packet #${esc(p.seq)}" aria-label="Export proof for packet ${esc(p.seq)}">${DL_ICON}</button>`
      : "";
    return `<div class="row row--${esc(p.status)}${provable ? " row--provable" : ""}" data-seq="${esc(p.seq)}">
      <span class="row__dot"></span>
      <span class="row__seq">#${esc(p.seq)}</span>
      <span class="row__flow">
        <span class="row__path">${esc(p.src_ip)} &rarr; ${esc(p.dst_ip)}</span>
        <span class="row__meta">${esc(p.protocol)} · ${fmtBytes(p.size)} · ttl ${esc(p.ttl)}</span>
      </span>
      <span class="row__right">
        <span class="row__hash">${esc((p.payload_hash || "").slice(0, 10))}…</span>${rules}${proofBtn}
      </span>
    </div>`;
  }

  function renderFeed(feed) {
    syncList($("feed"), feed.slice(0, FEED_MAX),
             (p) => `${p.seq}:${p.status}`, feedRow, "Waiting for traffic…");
  }

  function fmtBytes(n) {
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
    if (n >= 1024) return (n / 1024).toFixed(1) + " KB";
    return n + " B";
  }

  function alertCard(a) {
    const rep = a.report || {}, rem = a.remediation || {}, hard = a.hardening || {};
    const fixes = (rem.fixes || []).map((f) => `<li>${esc(f)}</li>`).join("");
    const autoTag = rem.auto_apply === "yes"
      ? `<span class="auto-tag">auto</span>`
      : (rem.auto_apply === "partial" ? `<span class="auto-tag">partial</span>` : "");
    const cmd = hard.command ? `<div class="alert__cmd">${esc(hard.command)}</div>` : "";
    const conf = rep.confidence != null
      ? `<span><b>${esc(rep.confidence)}%</b> confidence</span>` : "";
    const suspect = rep.suspect_hop
      ? `<span>suspect <b>${esc(rep.suspect_hop)}</b></span>` : "";
    const attack = rep.likely_attack ? `<span>${esc(rep.likely_attack)}</span>` : "";
    return `<article class="alert alert--${esc(a.severity)}">
      <div class="alert__top">
        <div class="alert__title">
          <span class="alert__rid">${esc(a.rule_id)}</span>
          <span class="sev sev--${esc(a.severity)}">${esc(a.severity)}</span>
          <span class="alert__name">${esc(a.name)}</span>
        </div>
        <span class="alert__time">${clock(a.timestamp)}
          ${a.seq >= 0 ? `<button class="proof-link" data-seq="${esc(a.seq)}" title="Export cryptographic proof for this packet">proof ${DL_ICON}</button>` : ""}
        </span>
      </div>
      <p class="alert__summary">${esc(a.summary)}</p>
      <div class="alert__trace">${suspect}${conf}${attack}</div>
      <div class="alert__fix">
        <span class="alert__fix-label">Recommended fix ${autoTag}</span>
        <ul>${fixes}</ul>${cmd}
      </div>
    </article>`;
  }

  function renderAlerts(alerts) {
    $("alertCount").textContent = alerts.length;
    syncList($("alerts"), alerts, (a) => a.id, alertCard, "No alerts. All clear.");
  }

  function renderDistribution(byRule) {
    const el = $("distribution");
    const entries = Object.entries(byRule || {}).sort((a, b) => b[1] - a[1]);
    if (!entries.length) { el.innerHTML = `<div class="empty">No incidents yet.</div>`; return; }
    const max = Math.max(...entries.map((e) => e[1]));
    el.innerHTML = entries.map(([rid, count]) => {
      const meta = RULES[rid] || { name: rid, sev: "LOW" };
      const w = Math.max(6, (count / max) * 100);
      return `<div class="bar">
        <span class="bar__label" title="${esc(rid)} ${esc(meta.name)}">${esc(meta.name)}</span>
        <span class="bar__track"><span class="bar__fill bar__fill--${meta.sev}" style="width:${w}%"></span></span>
        <span class="bar__val">${count}</span>
      </div>`;
    }).join("");
  }

  function renderThreatClass(byRule) {
    const el = $("threatClass");
    let ledger = 0, hygiene = 0;
    for (const [rid, n] of Object.entries(byRule || {})) {
      if (CLASS[rid] === "ledger") ledger += n;
      else if (CLASS[rid] === "hygiene") hygiene += n;
    }
    if (!ledger && !hygiene) { el.innerHTML = `<div class="empty">No incidents yet.</div>`; return; }
    const peak = Math.max(ledger, hygiene, 1);
    const bar = (label, n, mod) => `<div class="bar">
      <span class="bar__label">${label}</span>
      <span class="bar__track"><span class="bar__fill ${mod}" style="width:${Math.max(6, (n / peak) * 100)}%"></span></span>
      <span class="bar__val">${n}</span></div>`;
    el.innerHTML = bar("Ledger-caught", ledger, "") + bar("Network hygiene", hygiene, "bar__fill--hygiene");
  }

  function ledgerBlock(b) {
    const tag = b.index === 0 ? "genesis"
      : (b.packet_count ? `${b.packet_count} pkts` : "seq " + b.seq);
    return `<div class="block">
      <div class="block__head">
        <span class="block__idx">Block #${esc(b.index)}</span>
        <span class="block__seq">${esc(tag)}</span>
      </div>
      <div class="block__hash">${esc((b.hash || "").slice(0, 28))}…</div>
    </div>`;
  }

  function renderLedger(recent) {
    const blocks = (recent || []).slice().reverse();
    syncList($("ledger"), blocks, (b) => b.index, ledgerBlock, "Genesis pending…");
  }

  function renderSpark(processed) {
    if (lastProcessed !== null) {
      sparkData.push(Math.max(0, processed - lastProcessed));
      if (sparkData.length > SPARK_LEN) sparkData.shift();
    }
    lastProcessed = processed;
    const svg = $("spark");
    const W = 220, H = 56, n = sparkData.length;
    if (n < 2) { svg.innerHTML = ""; return; }
    const max = Math.max(1, ...sparkData);
    const step = W / (SPARK_LEN - 1);
    const pts = sparkData.map((v, i) => {
      const x = i * step;
      const y = H - 4 - (v / max) * (H - 10);
      return [x, y];
    });
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const area = line + ` L ${pts[pts.length - 1][0].toFixed(1)} ${H} L ${pts[0][0].toFixed(1)} ${H} Z`;
    const last = pts[pts.length - 1];
    svg.innerHTML = `
      <defs>
        <linearGradient id="sg" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0" stop-color="var(--accent)" stop-opacity="0.26"/>
          <stop offset="1" stop-color="var(--accent)" stop-opacity="0"/>
        </linearGradient>
        <filter id="sparkGlow" x="-20%" y="-60%" width="140%" height="220%">
          <feGaussianBlur stdDeviation="1.8" result="b"/>
          <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <path d="${area}" fill="url(#sg)"/>
      <path d="${line}" fill="none" stroke="var(--accent)" stroke-width="2"
            stroke-linejoin="round" stroke-linecap="round" filter="url(#sparkGlow)"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="3.2"
              fill="var(--accent)" filter="url(#sparkGlow)"/>`;
  }

  /* ------------------------------------------------------------------ Poll */
  async function refresh() {
    try {
      const [snap, health] = await Promise.all([
        fetch("/api/snapshot").then((r) => r.json()),
        fetch("/api/health").then((r) => r.json()).catch(() => null),
      ]);
      renderStats(snap);
      renderPills(snap, health);
      renderFeed(snap.feed);
      renderAlerts(snap.alerts);
      renderDistribution(snap.alert_stats.by_rule);
      renderThreatClass(snap.alert_stats.by_rule);
      renderLedger(snap.blockchain.recent);
      renderSpark(snap.stats.processed);
    } catch (e) {
      $("healthPill").className = "pill pill--crit";
      $("healthPillText").textContent = "Offline";
    }
  }

  function initProofAndQuorum() {
    $("proofBtn").addEventListener("click", () => exportProof(Number($("proofSeq").value)));
    $("proofSeq").addEventListener("keydown", (e) => {
      if (e.key === "Enter") exportProof(Number($("proofSeq").value));
    });
    // Delegated: "proof" buttons inside alerts.
    $("alerts").addEventListener("click", (e) => {
      const btn = e.target.closest(".proof-link");
      if (btn) {
        exportProof(Number(btn.dataset.seq));
        document.querySelector(".proof").scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
    // Delegated: click a verified/tampered feed row (or its proof button) to prove it.
    $("feed").addEventListener("click", (e) => {
      const el = e.target.closest(".row__proof, .row--provable");
      if (!el) return;
      const seq = Number(el.dataset.seq);
      if (!isNaN(seq)) {
        exportProof(seq);
        document.querySelector(".proof").scrollIntoView({ behavior: "smooth", block: "center" });
      }
    });
    // Compromise-a-witness demo.
    $("tamperBtn").addEventListener("click", async () => {
      const btn = $("tamperBtn");
      btn.disabled = true;
      try {
        const r = await fetch("/api/tamper-witness", { method: "POST" });
        const d = await r.json();
        if (d && d.status) {
          $("quorumDetail").textContent =
            `Forged W3 @seq ${d.seq} → quorum still ${d.status} (${d.agree}/${d.total}); W3 outvoted.`;
        }
      } catch (_) {}
      await refresh();
      setTimeout(() => { btn.disabled = false; }, 800);
    });
  }

  initTheme();
  initDemoToggle();
  initInject();
  initProofAndQuorum();
  refresh();
  setInterval(refresh, POLL_MS);
})();
