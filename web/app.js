(function () {
  "use strict";

  const cfg = window.CARDFORGE_CONFIG;
  const sb = window.supabase.createClient(cfg.supabaseUrl, cfg.supabaseAnonKey, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
  });

  const FORMATS = {
    W34: "34-bit · 16-bit site + 16-bit card",
    W26: "26-bit · 8-bit site + 16-bit card",
    RAW48: "48-bit · 16-bit site + 32-bit card"
  };

  // ------------------------------------------------------------------ state
  const S = {
    session: null,
    recovery: false,
    ctx: null,          // { installers, sites, stats, roles: {siteId: 'installer'|'owner'} }
    view: { page: "home" },
    site: null,         // loaded site detail { creds, changes, events, owners }
    busy: false
  };

  // ------------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtDate = iso => iso ? new Date(iso).toLocaleDateString("en-NZ", { day: "numeric", month: "short" }) : "";
  const fmtTime = iso => { const d = new Date(iso); return d.toLocaleDateString("en-NZ", { day: "numeric", month: "short" }) + " " + d.toLocaleTimeString("en-NZ", { hour: "2-digit", minute: "2-digit" }); };
  const app = () => $("#app");

  function toast(msg, isErr) {
    const t = $("#toast"); t.textContent = msg; t.classList.add("show");
    t.style.background = isErr ? "var(--bad)" : ""; t.style.color = isErr ? "#fff" : "";
    clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), isErr ? 5000 : 2800);
  }
  function errMsg(e) {
    if (!e) return "Something went wrong";
    const m = e.message || String(e);
    if (/Failed to fetch|NetworkError/i.test(m)) return "Can't reach the server. Check your connection.";
    return m;
  }
  async function rpc(name, args) {
    const { data, error } = await sb.rpc(name, args || {});
    if (error) throw error;
    return data;
  }
  async function fetchAll(query) {
    // PostgREST caps responses (1000 rows); page through.
    const out = []; const size = 1000;
    for (let from = 0; ; from += size) {
      const { data, error } = await query().range(from, from + size - 1);
      if (error) throw error;
      out.push(...data);
      if (data.length < size) return out;
    }
  }
  async function act(fn, okMsg) {
    if (S.busy) return;
    S.busy = true;
    try {
      await fn();
      if (okMsg) toast(okMsg);
    } catch (e) {
      toast(errMsg(e), true);
    } finally {
      S.busy = false;
    }
  }

  // ------------------------------------------------------------------ auth
  sb.auth.onAuthStateChange((event, session) => {
    S.session = session;
    if (event === "PASSWORD_RECOVERY") { S.recovery = true; renderRecovery(); return; }
    if (event === "SIGNED_OUT") { S.ctx = null; S.site = null; S.view = { page: "home" }; }
    if (event === "SIGNED_IN" || event === "INITIAL_SESSION" || event === "SIGNED_OUT") boot();
  });

  let booting = false;
  async function boot() {
    if (S.recovery) return;
    $("#who").textContent = S.session ? S.session.user.email : "";
    $("#signout").hidden = !S.session;
    if (!S.session) { renderAuth("signin"); return; }
    if (booting) return;
    booting = true;
    try {
      await rpc("claim_invites");
      await loadContext();
      routeFromHash();
      await render();
    } catch (e) {
      app().innerHTML = `<div class="auth"><h1>Couldn't load your account</h1><p class="err">${esc(errMsg(e))}</p><button class="btn" type="button" data-act="reload">Try again</button></div>`;
    } finally {
      booting = false;
    }
  }

  function renderAuth(mode, msg, isErr) {
    const signup = mode === "signup", reset = mode === "reset";
    app().innerHTML = `
      <section class="auth">
        <h1>${signup ? "Create your account" : reset ? "Reset password" : "Sign in"}</h1>
        <p>${signup ? "Installers set up their business after signing up. Site owners: use the email your installer invited." : reset ? "We'll email you a link to set a new password." : "Manage credential pools for your ICT sites."}</p>
        <form id="auth-form" novalidate>
          <div class="field"><label for="au-email">Email</label><input id="au-email" type="email" autocomplete="email" required></div>
          ${reset ? "" : `<div class="field"><label for="au-pass">Password</label><input id="au-pass" type="password" autocomplete="${signup ? "new-password" : "current-password"}" minlength="8" required>${signup ? `<span class="hint">At least 8 characters.</span>` : ""}</div>`}
          ${msg ? `<div class="${isErr ? "err" : "ok-msg"}">${esc(msg)}</div>` : ""}
          <button class="btn primary" type="submit">${signup ? "Create account" : reset ? "Send reset link" : "Sign in"}</button>
        </form>
        <div class="row" style="display:flex;gap:14px;flex-wrap:wrap;font-size:14px">
          ${signup || reset ? `<button class="link" type="button" data-auth="signin">I already have an account</button>` : `<button class="link" type="button" data-auth="signup">Create an account</button><button class="link" type="button" data-auth="reset">Forgot password</button>`}
        </div>
      </section>`;
    $("#au-email").focus();
    $("#auth-form").addEventListener("submit", async e => {
      e.preventDefault();
      const email = $("#au-email").value.trim();
      const pass = reset ? "" : $("#au-pass").value;
      if (!email || (!reset && pass.length < (signup ? 8 : 1))) { renderAuth(mode, signup ? "Enter your email and a password of 8+ characters." : "Enter your email and password.", true); return; }
      const btn = e.target.querySelector("button[type=submit]"); btn.disabled = true;
      try {
        if (signup) {
          const { data, error } = await sb.auth.signUp({ email, password: pass, options: { emailRedirectTo: location.origin + location.pathname } });
          if (error) throw error;
          if (!data.session) renderAuth("signin", "Check your email and tap the confirmation link, then sign in here.");
        } else if (reset) {
          const { error } = await sb.auth.resetPasswordForEmail(email, { redirectTo: location.origin + location.pathname });
          if (error) throw error;
          renderAuth("signin", "If that email has an account, a reset link is on its way.");
        } else {
          const { error } = await sb.auth.signInWithPassword({ email, password: pass });
          if (error) throw error;
        }
      } catch (err) {
        renderAuth(mode, /Invalid login/i.test(errMsg(err)) ? "Email or password is wrong." : /not confirmed/i.test(errMsg(err)) ? "Confirm your email first (check your inbox)." : errMsg(err), true);
      }
    });
  }

  function renderRecovery(msg) {
    app().innerHTML = `
      <section class="auth"><h1>Set a new password</h1>
        <form id="rec-form"><div class="field"><label for="rec-pass">New password</label><input id="rec-pass" type="password" minlength="8" autocomplete="new-password" required></div>
        ${msg ? `<div class="err">${esc(msg)}</div>` : ""}
        <button class="btn primary" type="submit">Save password</button></form></section>`;
    $("#rec-form").addEventListener("submit", async e => {
      e.preventDefault();
      const p = $("#rec-pass").value;
      if (p.length < 8) { renderRecovery("Use at least 8 characters."); return; }
      const { error } = await sb.auth.updateUser({ password: p });
      if (error) { renderRecovery(errMsg(error)); return; }
      S.recovery = false; toast("Password updated."); boot();
    });
  }

  // ------------------------------------------------------------------ data
  async function loadContext() {
    const uid = S.session.user.id;
    const [mem, inst, sites, stats] = await Promise.all([
      sb.from("memberships").select("*").eq("user_id", uid),
      sb.from("installers").select("*").order("name"),
      sb.from("sites").select("*").order("name"),
      sb.from("site_stats").select("*")
    ]);
    for (const r of [mem, inst, sites, stats]) if (r.error) throw r.error;
    const myInstallers = new Set(mem.data.filter(m => m.role === "installer").map(m => m.installer_id));
    const ownerSites = new Set(mem.data.filter(m => m.role === "owner").map(m => m.site_id));
    const roles = {};
    sites.data.forEach(s => { roles[s.id] = myInstallers.has(s.installer_id) ? "installer" : ownerSites.has(s.id) ? "owner" : null; });
    const statMap = {}; stats.data.forEach(x => { statMap[x.site_id] = x; });
    S.ctx = {
      installers: inst.data.filter(i => myInstallers.has(i.id)),
      allInstallers: inst.data,
      sites: sites.data, stats: statMap, roles,
      isInstaller: myInstallers.size > 0
    };
  }

  async function loadSite(id) {
    const [creds, changes, events] = await Promise.all([
      fetchAll(() => sb.from("credentials").select("*").eq("site_id", id).order("card_number")),
      sb.from("panel_changes").select("*").eq("site_id", id).order("created_at", { ascending: false }).limit(300),
      sb.from("events").select("*").eq("site_id", id).order("created_at", { ascending: false }).limit(100)
    ]);
    if (changes.error) throw changes.error;
    if (events.error) throw events.error;
    let owners = null;
    if (S.ctx.roles[id] === "installer") owners = await rpc("site_owners", { p_site: id });
    S.site = { id, creds, changes: changes.data, events: events.data, owners };
  }

  async function refresh() {
    await loadContext();
    if (S.view.page === "site") {
      if (!S.ctx.roles[S.view.id]) { S.view = { page: "home" }; }
      else await loadSite(S.view.id);
    }
    paint();
  }

  // ------------------------------------------------------------------ routing
  function routeFromHash() {
    const m = /^#site-([0-9a-f-]{36})$/.exec(location.hash);
    if (m && S.ctx.roles[m[1]]) S.view = { page: "site", id: m[1], tab: "creds", filter: "all" };
    else if (!S.ctx.isInstaller && S.ctx.sites.length === 1) S.view = { page: "site", id: S.ctx.sites[0].id, tab: "creds", filter: "all" };
    else S.view = { page: "home" };
  }
  window.addEventListener("hashchange", () => { if (S.ctx) { routeFromHash(); render(); } });

  async function go(view) {
    S.view = view;
    const h = view.page === "site" ? "#site-" + view.id : "";
    if (location.hash !== h) history.replaceState(null, "", location.pathname + h);
    await render();
    window.scrollTo(0, 0);
  }

  async function render() {
    if (S.view.page === "site") {
      app().innerHTML = `<div class="loading">Loading site…</div>`;
      try { await loadSite(S.view.id); } catch (e) { toast(errMsg(e), true); S.view = { page: "home" }; }
    }
    paint();
  }

  function paint() {
    if (!S.ctx) return;
    if (!S.ctx.isInstaller && S.ctx.sites.length === 0) { app().innerHTML = onboardingView(); return; }
    app().innerHTML = S.view.page === "site" && S.site ? siteView() : homeView();
  }

  // ------------------------------------------------------------------ views
  function poolBar(st) {
    const total = Number(st.total) || 0;
    const seg = (k, v) => v ? `<span style="width:${(v / total * 100).toFixed(2)}%;background:var(${k})"></span>` : "";
    return `<div class="bar" role="img" aria-label="${st.assigned} assigned, ${st.available} available, ${st.quarantine} in quarantine, ${st.retired} retired">${seg("--info", +st.assigned)}${seg("--ok", +st.available)}${seg("--warn", +st.quarantine)}${seg("--grey", +st.retired)}</div>
      <div class="legend"><span><i style="background:var(--info)"></i>${st.assigned} assigned</span><span><i style="background:var(--ok)"></i>${st.available} available</span><span><i style="background:var(--warn)"></i>${st.quarantine} quarantine</span><span><i style="background:var(--grey)"></i>${st.retired} retired</span></div>`;
  }
  const emptyStats = { total: 0, available: 0, assigned: 0, quarantine: 0, retired: 0, pending_changes: 0 };
  const statsOf = id => S.ctx.stats[id] || emptyStats;

  function onboardingView() {
    return `
      <section class="auth">
        <h1>Welcome</h1>
        <p>You're signed in as <b>${esc(S.session.user.email)}</b>, but you're not linked to any site yet.</p>
        <p><b>Site owner?</b> Ask your installer to add this email to your site, then reload.</p>
        <form id="inst-form"><div class="field"><label for="in-name">Installer? Name your business</label><input id="in-name" type="text" placeholder="e.g. Coast Security Ltd" required></div>
          <button class="btn primary" type="submit">Create installer account</button></form>
        <button class="btn" type="button" data-act="reload">Reload</button>
      </section>`;
  }

  function homeView() {
    const sites = S.ctx.sites;
    const all = sites.map(s => statsOf(s.id));
    const sum = k => all.reduce((a, b) => a + Number(b[k] || 0), 0);
    const requests = sites.filter(s => s.topup_requested && S.ctx.roles[s.id] === "installer").length;
    const title = S.ctx.installers.length ? S.ctx.installers.map(i => i.name).join(", ") : "Your sites";
    return `
      <div class="section-head"><div><h1>${esc(title)}</h1><p>${sites.length} site${sites.length === 1 ? "" : "s"} · ${sum("total")} credentials in pools</p></div>
        ${S.ctx.isInstaller ? `<button class="btn primary" data-act="new-site" type="button">Add site</button>` : ""}</div>
      <div class="tiles">
        <div class="tile" style="--c:var(--info)"><div class="k">Assigned</div><div class="v">${sum("assigned")}</div><div class="s">people with access</div></div>
        <div class="tile" style="--c:var(--ok)"><div class="k">Available</div><div class="v">${sum("available")}</div><div class="s">ready to assign</div></div>
        <div class="tile" style="--c:var(--warn)"><div class="k">Quarantine</div><div class="v">${sum("quarantine")}</div><div class="s">waiting to be cleaned</div></div>
        <div class="tile" style="--c:${sum("pending_changes") ? "var(--bad)" : "var(--line)"}"><div class="k">Panel changes</div><div class="v">${sum("pending_changes")}</div><div class="s">to do in Protege${requests ? ` · ${requests} top-up request${requests > 1 ? "s" : ""}` : ""}</div></div>
      </div>
      ${sites.length ? `<div class="sites">${sites.map(siteCard).join("")}</div>` : `<div class="note">No sites yet. Add your first site to create its credential pool.</div>`}
      <div class="note"><b>How a credential moves:</b>
        <div class="lifecycle" style="margin-top:6px"><span class="pill p-available">Available</span>→<span class="pill p-assigned">Assigned</span>→<span class="pill p-quarantine">Quarantine</span>→ removed from panel + carrier wiped →<span class="pill p-available">Back in pool</span>
        <span style="flex-basis:100%"></span>Lost or stolen →<span class="pill p-retired">Retired</span> (the number is never reused)</div></div>`;
  }

  function siteCard(s) {
    const st = statsOf(s.id), low = Number(st.available) <= 2, isInst = S.ctx.roles[s.id] === "installer";
    const range = st.min_card != null ? ` · cards <span class="num">${st.min_card}–${st.max_card}</span>` : "";
    return `<article class="site">
      <div class="site-top"><div><h2>${esc(s.name)}</h2><div class="meta">Site code <span class="num">${s.site_code}</span> · ${s.format}${range}${isInst ? "" : " · you're the site owner"}</div></div></div>
      ${poolBar(st)}
      <div class="row">${s.topup_requested ? `<span class="flag">Top-up requested</span>` : ""}${low ? `<span class="flag bad">Pool low: ${st.available} left</span>` : ""}${+st.pending_changes ? `<span class="flag">${st.pending_changes} panel change${+st.pending_changes > 1 ? "s" : ""}</span>` : ""}</div>
      <div class="row"><button class="btn small primary" data-act="open-site" data-site="${s.id}" type="button">Open site</button>${isInst ? `<button class="btn small" data-act="topup" data-site="${s.id}" type="button">Top up pool</button>` : ""}</div>
    </article>`;
  }

  function currentSite() { return S.ctx.sites.find(s => s.id === S.view.id); }

  function siteView() {
    const s = currentSite(), st = statsOf(s.id), role = S.ctx.roles[s.id], isInst = role === "installer";
    const tab = S.view.tab || "creds";
    const inst = S.ctx.allInstallers.find(i => i.id === s.installer_id);
    const tabs = [["creds", "Credentials", st.total, false], ["changes", "Panel changes", st.pending_changes, +st.pending_changes > 0], ["activity", "Activity", null, false]];
    if (isInst) tabs.push(["owners", "Site owners", S.site.owners ? S.site.owners.length : 0, false]);
    const showBack = S.ctx.isInstaller || S.ctx.sites.length > 1;
    return `
      ${showBack ? `<div class="crumb"><button class="link" data-act="home" type="button">All sites</button> / ${esc(s.name)}</div>` : ""}
      <section class="site-head">
        <div class="line1"><div><h1>${esc(s.name)}</h1>
          <div class="chips" style="margin-top:6px"><span class="chip">Site code <span class="num">${s.site_code}</span></span><span class="chip">${FORMATS[s.format]}</span>${inst ? `<span class="chip">Installer: ${esc(inst.name)}</span>` : ""}<span class="chip">You: ${isInst ? "installer" : "site owner"}</span></div></div>
          <div class="row" style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn primary" data-act="assign" type="button" ${+st.available ? "" : "disabled"}>Assign credential</button>
            ${isInst ? `<button class="btn" data-act="topup" data-site="${s.id}" type="button">Top up pool</button>` : `<button class="btn" data-act="request-topup" type="button" ${s.topup_requested ? "disabled" : ""}>${s.topup_requested ? "Top-up requested" : "Request more credentials"}</button>`}
          </div></div>
        ${poolBar(st)}
        ${+st.available <= 2 ? `<div class="flag bad" style="justify-self:start">Only ${st.available} credential${+st.available === 1 ? "" : "s"} left in the pool${isInst ? "." : ". Request more before you run out."}</div>` : ""}
      </section>
      <div class="tabs" role="tablist">${tabs.map(t => `<button role="tab" type="button" data-act="tab" data-tab="${t[0]}" aria-selected="${tab === t[0]}">${t[1]}${t[2] != null ? `<span class="count${t[3] ? " hot" : ""}">${t[2]}</span>` : ""}</button>`).join("")}</div>
      ${tab === "creds" ? credsTab(s) : tab === "changes" ? changesTab(s) : tab === "owners" ? ownersTab(s) : activityTab()}`;
  }

  function credsTab(s) {
    const f = S.view.filter || "all", q = (S.view.q || "").toLowerCase();
    const creds = S.site.creds;
    const count = k => creds.filter(c => c.status === k).length;
    const order = { quarantine: 0, assigned: 1, available: 2, retired: 3 };
    let rows = creds.filter(c => (f === "all" || c.status === f) && (!q || String(c.card_number).includes(q) || (c.holder_name && c.holder_name.toLowerCase().includes(q)) || (c.holder_email && c.holder_email.includes(q))));
    rows.sort((a, b) => (order[a.status] - order[b.status]) || (a.card_number - b.card_number));
    const LIMIT = 300, shown = rows.slice(0, LIMIT);
    const fbtn = (k, label, n) => `<button type="button" data-act="filter" data-filter="${k}" aria-pressed="${f === k}">${label} <span class="num">${n}</span></button>`;
    return `
      <div class="toolbar">
        <div class="filter">${fbtn("all", "All", creds.length)}${fbtn("assigned", "Assigned", count("assigned"))}${fbtn("available", "Available", count("available"))}${fbtn("quarantine", "Quarantine", count("quarantine"))}${fbtn("retired", "Retired", count("retired"))}</div>
        <span class="grow"></span>
        <input type="search" id="q" placeholder="Search name, email or number" value="${esc(S.view.q || "")}" aria-label="Search credentials">
      </div>
      <div class="ledger">
        <div class="lrow head"><div>Credential</div><div>Status</div><div>Holder</div><div>Carrier</div><div></div></div>
        ${shown.length ? shown.map(c => credRow(s, c)).join("") : `<div class="empty">No credentials match.</div>`}
        ${rows.length > LIMIT ? `<div class="empty">Showing ${LIMIT} of ${rows.length}. Search or filter to narrow down.</div>` : ""}
      </div>`;
  }

  function credRow(s, c) {
    const stLabel = { available: "Available", assigned: "Assigned", quarantine: "Quarantine", retired: "Retired" }[c.status];
    let holder = `<span style="color:var(--muted)">-</span>`, carrier = holder, actions = "";
    if (c.holder_name && c.status !== "available") {
      const sub = c.status === "assigned" ? "since " + fmtDate(c.assigned_at) + (c.expires_on ? " · expires " + fmtDate(c.expires_on) : "")
        : c.status === "retired" ? (c.retired_reason || "Retired") + " " + fmtDate(c.freed_at) : "freed " + fmtDate(c.freed_at);
      holder = `<div class="holder"><b>${esc(c.holder_name)}</b><small>${esc(sub)}</small></div>`;
    }
    if (c.carrier && c.status !== "available") {
      const isPhone = c.carrier === "phone";
      const state = c.status === "assigned" ? (c.ready ? (isPhone ? "Set up on phone" : "Encoded & handed over") : `<span class="todo">${isPhone ? "Not set up on phone yet" : "Card not encoded yet"}</span>`) : "";
      carrier = `<div class="carrier">${isPhone ? "Phone" : "Card / fob"}<small>${state}</small></div>`;
    }
    if (c.status === "available") actions = `<button class="btn small primary" data-act="assign" data-id="${c.id}" type="button">Assign</button>`;
    if (c.status === "assigned") {
      if (!c.ready) actions += `<button class="btn small" data-act="deliver" data-id="${c.id}" type="button">${c.carrier === "phone" ? "Set up phone" : "Encode card"}</button>`;
      actions += `<button class="btn small" data-act="unassign" data-id="${c.id}" type="button">Unassign</button>`;
    }
    if (c.status === "quarantine") {
      const left = (!c.check_panel) + (!c.check_carrier);
      actions = `<button class="btn small ${left ? "" : "primary"}" data-act="clean" data-id="${c.id}" type="button">${left ? `Clean up (${left} step${left > 1 ? "s" : ""})` : "Return to pool"}</button>`;
    }
    const reuse = c.reuse_count ? `<small>reused ×${c.reuse_count}</small>` : "";
    return `<div class="lrow"><div class="credno">${s.site_code}/${c.card_number}${reuse}</div><div><span class="pill p-${c.status}">${stLabel}</span></div><div>${holder}</div><div>${carrier}</div><div class="actions">${actions}</div></div>`;
  }

  function changesTab(s) {
    const pend = S.site.changes.filter(c => !c.done), done = S.site.changes.filter(c => c.done).slice(0, 15);
    const row = ch => `<div class="li"><span class="op ${ch.op}">${ch.op === "add" ? "ADD" : "REMOVE"}</span>
      <div class="grow"><b class="num">Card ${s.site_code}/${ch.card_number}</b> ${ch.op === "add" ? "for" : "from"} ${esc(ch.holder_name || "")}<small>${ch.note ? esc(ch.note) : ch.op === "add" ? "Enrol this card number on the user in Protege" : "Delete this card number from the user in Protege"} · ${fmtTime(ch.created_at)}</small></div>
      ${ch.done ? `<span class="done-txt">${ch.note ? "Cancelled" : "Done"}</span>` : `<button class="btn small primary" data-act="change-done" data-change="${ch.id}" type="button">Mark done in Protege</button>`}</div>`;
    return `
      <div class="note">The ICT reader only passes the card number to the panel, so the panel decides who gets in. Until there's a Protege API sync, each change here is a quick step to do in Protege GX/WX.</div>
      <div class="list">${pend.length ? pend.map(row).join("") : `<div class="empty">Panel is up to date.</div>`}</div>
      ${done.length ? `<h3>Recently done</h3><div class="list">${done.map(row).join("")}</div>` : ""}`;
  }

  function activityTab() {
    const ev = S.site.events;
    return `<div class="list">${ev.length ? ev.map(e => `<div class="li"><span class="time">${fmtTime(e.created_at)}</span><div class="grow">${esc(e.message)}</div></div>`).join("") : `<div class="empty">No activity yet.</div>`}</div>`;
  }

  function ownersTab(s) {
    const o = S.site.owners || [];
    return `
      <div class="note">Site owners can assign, unassign and clean up credentials for <b>${esc(s.name)}</b>, and request more. Only you can top up the pool. Invited people get access when they create an account with that email.</div>
      <form class="owners-form" id="owner-form"><input id="ow-email" type="email" placeholder="owner@business.co.nz" aria-label="Owner email" required><button class="btn primary" type="submit">Add owner</button></form>
      <div class="list">${o.length ? o.map(x => `<div class="li"><div class="grow"><b>${esc(x.email)}</b><small>${x.status === "active" ? "Has access" : "Invited, hasn't signed up yet"}</small></div><button class="btn small danger" type="button" data-act="remove-owner" data-email="${esc(x.email)}">Remove</button></div>`).join("") : `<div class="empty">No site owners yet.</div>`}</div>`;
  }

  // ------------------------------------------------------------------ dialogs
  let lastFocus = null;
  function openDialog(html, onMount) {
    lastFocus = document.activeElement;
    const d = $("#dialog"); d.innerHTML = html; $("#scrim").classList.add("open");
    if (onMount) onMount(d);
    const f = d.querySelector("input:not([type=hidden]):not([type=radio]), select, button.primary, button"); if (f) f.focus();
  }
  function closeDialog() { $("#scrim").classList.remove("open"); $("#dialog").innerHTML = ""; if (lastFocus && lastFocus.focus) lastFocus.focus(); }
  const cred = id => S.site.creds.find(c => c.id === id);

  function assignDialog(s, preferred) {
    const avail = S.site.creds.filter(c => c.status === "available").sort((a, b) => (a.reuse_count - b.reuse_count) || (a.card_number - b.card_number));
    if (!avail.length) { toast("No credentials left in the pool.", true); return; }
    const pick = preferred || avail[0];
    const today = new Date().toISOString().slice(0, 10);
    openDialog(`
      <h2 id="dlg-title">Assign credential</h2>
      <div class="bignum">${s.site_code}/${pick.card_number}<small>${preferred ? "Selected" : "Next in pool"}${pick.reuse_count ? ` · recycled ×${pick.reuse_count}` : " · never used"}</small></div>
      <form id="assign-form" style="display:grid;gap:12px">
        <div class="field"><label for="a-name">Person's name</label><input id="a-name" type="text" required autocomplete="off"></div>
        <div class="field"><label for="a-email">Email</label><input id="a-email" type="email" required autocomplete="off"></div>
        <div class="field"><span style="font-size:13px;font-weight:600">Carrier</span>
          <div class="radio-cards">
            <label><input type="radio" name="carrier" value="phone" checked><b>Phone</b><small>CardForge app, Phone tab (Android NFC)</small></label>
            <label><input type="radio" name="carrier" value="card"><b>Card / fob</b><small>Encode with CardForge, then hand over</small></label>
          </div></div>
        <div class="field"><label for="a-exp">Expires (optional)</label><input id="a-exp" type="date" min="${today}"></div>
        <div class="err" id="a-err" hidden></div>
        <div class="foot"><button type="button" class="btn" data-act="close">Cancel</button><button type="submit" class="btn primary">Assign ${s.site_code}/${pick.card_number}</button></div>
      </form>`, d => {
      $("#assign-form", d).addEventListener("submit", e => {
        e.preventDefault();
        act(async () => {
          const c = await rpc("assign_credential", {
            p_site: s.id, p_name: $("#a-name", d).value, p_email: $("#a-email", d).value,
            p_carrier: d.querySelector("input[name=carrier]:checked").value,
            p_expires: $("#a-exp", d).value || null, p_card: preferred ? preferred.card_number : null
          });
          await refresh();
          deliverDialog(s, cred(c.id) || c);
        });
      });
    });
  }

  function deliverDialog(s, c) {
    const isPhone = c.carrier === "phone";
    openDialog(`
      <h2 id="dlg-title">${isPhone ? "Set up the phone" : "Encode the card"}</h2>
      <p style="margin:0">${isPhone
        ? `On <b>${esc(c.holder_name)}</b>'s Android phone, open CardForge → <b>Phone</b> tab, enter these numbers, tap <b>Save phone credential</b> and switch it on.`
        : `Open CardForge → <b>Encode</b>, write these numbers to a blank DESFire card or fob, then hand it to <b>${esc(c.holder_name)}</b>.`}</p>
      <dl class="kv"><dt>Site code</dt><dd>${s.site_code}</dd><dt>Card ID</dt><dd>${c.card_number}</dd><dt>Format</dt><dd>${s.format}</dd></dl>
      <p style="margin:0;font-size:13px;color:var(--muted)">Then do the matching "ADD" step in Panel changes so the door accepts it.</p>
      <div class="foot"><button class="btn" type="button" data-act="close">Later</button><button class="btn primary" type="button" data-act="mark-ready" data-id="${c.id}">${isPhone ? "Phone is set up" : "Card encoded & handed over"}</button></div>`);
  }

  function unassignDialog(s, c) {
    openDialog(`
      <h2 id="dlg-title">Unassign ${s.site_code}/${c.card_number}</h2>
      <p style="margin:0">${esc(c.holder_name)} · ${c.carrier === "phone" ? "phone" : "card or fob"}</p>
      <div class="field"><span style="font-size:13px;font-weight:600">What happened?</span>
        <div class="radio-cards">
          <label><input type="radio" name="why" value="returned" checked><b>${c.carrier === "phone" ? "No longer needed" : "Card returned"}</b><small>Cleans up, then goes back in the pool</small></label>
          <label><input type="radio" name="why" value="lost"><b>Lost or stolen</b><small>Retired. This number is never reused</small></label>
        </div></div>
      <div class="foot"><button class="btn" type="button" data-act="close">Cancel</button><button class="btn primary" type="button" data-act="do-unassign" data-id="${c.id}">Unassign</button></div>`);
  }

  function cleanDialog(s, c) {
    const isPhone = c.carrier === "phone";
    openDialog(`
      <h2 id="dlg-title">Clean up ${s.site_code}/${c.card_number}</h2>
      <p style="margin:0">Last held by ${esc(c.holder_name)}. It goes back in the pool once both steps are done, so the old ${isPhone ? "phone" : "card"} can't open doors.</p>
      <label class="check"><input type="checkbox" id="ck-panel" ${c.check_panel ? "checked" : ""}><span><b>Removed from the Protege panel</b><small>Card number deleted from the user record. Also ticks off the matching panel change.</small></span></label>
      <label class="check"><input type="checkbox" id="ck-carrier" ${c.check_carrier ? "checked" : ""}><span><b>${isPhone ? "Phone credential removed" : "Card wiped with CardForge"}</b><small>${isPhone ? "Switch off and clear it in the CardForge Phone tab." : "CardForge → Wipe, or bin the card."}</small></span></label>
      <div class="foot"><button class="btn" type="button" data-act="close">Close</button><button class="btn primary" type="button" data-act="return-pool" data-id="${c.id}" ${c.check_panel && c.check_carrier ? "" : "disabled"}>Return to pool</button></div>`, d => {
      const sync = () => act(async () => {
        const v = await rpc("set_cleanup", { p_credential: c.id, p_panel: $("#ck-panel", d).checked, p_carrier: $("#ck-carrier", d).checked });
        $("[data-act=return-pool]", d).disabled = !(v.check_panel && v.check_carrier);
        await refresh();
      });
      $("#ck-panel", d).addEventListener("change", sync);
      $("#ck-carrier", d).addEventListener("change", sync);
    });
  }

  function topupDialog(s) {
    const st = statsOf(s.id);
    const from = (st.max_card != null ? Number(st.max_card) : 1000) + 1;
    openDialog(`
      <h2 id="dlg-title">Top up ${esc(s.name)}</h2>
      <p style="margin:0">Adds new card numbers to this site's pool. Billing is handled outside the app for now.</p>
      <form id="topup-form" style="display:grid;gap:12px">
        <div class="field"><label for="t-n">How many credentials?</label><input id="t-n" type="number" min="1" max="1000" value="10" required></div>
        <div class="bignum" id="t-range">${s.site_code}/${from} – ${s.site_code}/${from + 9}<small>new numbers</small></div>
        <div class="foot"><button type="button" class="btn" data-act="close">Cancel</button><button type="submit" class="btn primary">Add to pool</button></div>
      </form>`, d => {
      const inp = $("#t-n", d);
      const n = () => Math.max(1, Math.min(1000, parseInt(inp.value || "1", 10) || 1));
      inp.addEventListener("input", () => { $("#t-range", d).innerHTML = `${s.site_code}/${from} – ${s.site_code}/${from + n() - 1}<small>new numbers</small>`; });
      $("#topup-form", d).addEventListener("submit", e => {
        e.preventDefault();
        const count = n();
        act(async () => { await rpc("topup_pool", { p_site: s.id, p_count: count }); closeDialog(); await refresh(); }, `${count} credentials added to ${s.name}.`);
      });
    });
  }

  function newSiteDialog() {
    const inst = S.ctx.installers[0];
    const codes = S.ctx.sites.filter(s => s.installer_id === inst.id).map(s => s.site_code);
    const next = codes.length ? Math.max(...codes) + 1 : 1;
    openDialog(`
      <h2 id="dlg-title">Add site</h2>
      <form id="site-form" style="display:grid;gap:12px">
        <div class="field"><label for="s-name">Site name</label><input id="s-name" type="text" required></div>
        <div class="field"><label for="s-code">Site code</label><input id="s-code" type="number" min="0" max="65535" value="${next}" required><span class="hint">Must match the site code you encode on this site's cards and phones.</span></div>
        <div class="field"><label for="s-fmt">Card format</label><select id="s-fmt">${Object.keys(FORMATS).map(k => `<option value="${k}" ${k === "W34" ? "selected" : ""}>${FORMATS[k]}</option>`).join("")}</select><span class="hint">Must match the format set in CardForge Keys and the reader's format slot.</span></div>
        <div class="field"><label for="s-n">Starting pool size</label><input id="s-n" type="number" min="1" max="1000" value="20" required></div>
        <div class="foot"><button type="button" class="btn" data-act="close">Cancel</button><button type="submit" class="btn primary">Create site</button></div>
      </form>`, d => {
      $("#site-form", d).addEventListener("submit", e => {
        e.preventDefault();
        act(async () => {
          const id = await rpc("create_site", {
            p_installer: inst.id, p_name: $("#s-name", d).value, p_site_code: parseInt($("#s-code", d).value, 10),
            p_format: $("#s-fmt", d).value, p_pool_size: parseInt($("#s-n", d).value, 10)
          });
          closeDialog(); await loadContext(); await go({ page: "site", id, tab: "creds", filter: "all" });
        }, "Site created.");
      });
    });
  }

  function confirmDialog(title, body, okLabel, onOk) {
    openDialog(`<h2 id="dlg-title">${esc(title)}</h2><p style="margin:0">${body}</p>
      <div class="foot"><button class="btn" type="button" data-act="close">Cancel</button><button class="btn primary" type="button" id="cf-ok">${esc(okLabel)}</button></div>`,
      d => { $("#cf-ok", d).addEventListener("click", onOk); });
  }

  // ------------------------------------------------------------------ events
  document.addEventListener("click", e => {
    const a = e.target.closest("[data-auth]");
    if (a) { renderAuth(a.dataset.auth); return; }
    const b = e.target.closest("[data-act]"); if (!b) return;
    const s = S.view.page === "site" ? currentSite() : null;
    const c = S.site && b.dataset.id ? cred(b.dataset.id) : null;
    switch (b.dataset.act) {
      case "reload": location.reload(); break;
      case "home": go({ page: "home" }); break;
      case "open-site": go({ page: "site", id: b.dataset.site, tab: "creds", filter: "all" }); break;
      case "tab": S.view.tab = b.dataset.tab; paint(); break;
      case "filter": S.view.filter = b.dataset.filter; paint(); break;
      case "close": closeDialog(); break;
      case "new-site": newSiteDialog(); break;
      case "topup": topupDialog(S.ctx.sites.find(x => x.id === (b.dataset.site || S.view.id))); break;
      case "request-topup": act(async () => { await rpc("request_topup", { p_site: s.id }); await refresh(); }, "Request sent to your installer."); break;
      case "assign": assignDialog(s, c); break;
      case "deliver": deliverDialog(s, c); break;
      case "mark-ready": act(async () => { await rpc("mark_ready", { p_credential: b.dataset.id }); closeDialog(); await refresh(); }, "Credential is live. Remember the panel change."); break;
      case "unassign": unassignDialog(s, c); break;
      case "do-unassign": {
        const why = $("#dialog input[name=why]:checked").value;
        act(async () => { await rpc("unassign_credential", { p_credential: b.dataset.id, p_reason: why }); closeDialog(); await refresh(); },
          why === "lost" ? "Retired. That number will never be reissued." : "Moved to quarantine.");
        break;
      }
      case "clean":
        if (c.check_panel && c.check_carrier) act(async () => { await rpc("return_to_pool", { p_credential: c.id }); await refresh(); }, "Back in the pool.");
        else cleanDialog(s, c);
        break;
      case "return-pool": act(async () => { await rpc("return_to_pool", { p_credential: b.dataset.id }); closeDialog(); await refresh(); }, "Back in the pool."); break;
      case "change-done": act(async () => { await rpc("mark_change_done", { p_change: Number(b.dataset.change) }); await refresh(); }); break;
      case "remove-owner": {
        const email = b.dataset.email;
        confirmDialog("Remove site owner?", `${esc(email)} will lose access to ${esc(s.name)}.`, "Remove", () =>
          act(async () => { await rpc("remove_site_owner", { p_site: s.id, p_email: email }); closeDialog(); await refresh(); }, "Owner removed."));
        break;
      }
    }
  });

  document.addEventListener("submit", e => {
    if (e.target.id === "inst-form") {
      e.preventDefault();
      act(async () => { await rpc("create_installer", { p_name: $("#in-name").value }); await loadContext(); await go({ page: "home" }); }, "Installer account created.");
    }
    if (e.target.id === "owner-form") {
      e.preventDefault();
      const s = currentSite(), email = $("#ow-email").value;
      act(async () => {
        const r = await rpc("add_site_owner", { p_site: s.id, p_email: email });
        await refresh();
        toast(r === "added" ? "Owner added. They'll see the site next time they sign in." : "Invited. They get access once they sign up with that email.");
      });
    }
  });

  document.addEventListener("input", e => {
    if (e.target.id === "q") {
      S.view.q = e.target.value; const pos = e.target.selectionStart; paint();
      const q = $("#q"); if (q) { q.focus(); q.setSelectionRange(pos, pos); }
    }
  });
  document.addEventListener("keydown", e => { if (e.key === "Escape" && $("#scrim").classList.contains("open")) closeDialog(); });
  $("#scrim").addEventListener("click", e => { if (e.target.id === "scrim") closeDialog(); });
  $("#signout").addEventListener("click", () => sb.auth.signOut());
})();
