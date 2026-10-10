/* Hub Mgmt panel - talks only to hub_mgmt/* websocket commands. */
(() => {
  if (customElements.get("hub-mgmt-panel")) return;

  const TABS = [
    ["overview", "Summary"],
    ["pairing", "Pairing"],
    ["devices", "Devices"],
    ["discovered", "Discovered"],
  ];

  class HubInstallerPanel extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: "open" });
      this._tab = "overview";
      this._status = {};
      this._devices = [];
      this._areas = [];
      this._flows = [];
      this._flow = null; // active flow step
      this._msg = "";
      this._busy = false;
      this._top = "hub";
      this._tr = { models: [], model: null, data: null, imgs: {}, sel: new Set(), msg: "", view: "browse", limit: {}, filter: "", lab: "", dsel: new Set() };
      this._users = [];
      this._assignable = [];
      this._reset = null;
      this._usig = "";
      this._me = null;
      this._hub = {};
      this._net = null;
      this._edits = {};
      this._f = { name: "", model: "", protocol: "", area: "", state: "", newOnly: false, showIgnored: false, unusedOnly: false };
      this._sort = { key: null, dir: 1 };
      this._timer = null;
      this._built = false;
    }

    set hass(h) {
      const first = !this._hass;
      this._hass = h;
      if (first) {
        this._build();
        this._refresh();
        this._timer = setInterval(() => this._refresh(true), 3000);
      }
    }
    set narrow(_) {}
    set route(_) {}
    set panel(_) {}
    disconnectedCallback() { clearInterval(this._timer); this._timer = null; }
    connectedCallback() {
      if (this._hass && !this._timer) this._timer = setInterval(() => this._refresh(true), 3000);
    }

    async _ws(type, extra = {}) {
      return this._hass.callWS({ type: `hub_mgmt/${type}`, ...extra });
    }

    async _refresh(quiet) {
      try {
        if (!this._me) this._me = await this._ws("whoami");
        this._hub = await this._ws("hub_stats");
        if (this._me.installer) {
          const [status, devices, flows] = await Promise.all([
            this._ws("status"), this._ws("devices"), this._ws("flows"),
          ]);
          this._status = status; this._devices = devices; this._flows = flows;
          if (!this._areas.length) this._areas = await this._ws("areas");
        }
        if (this._me.installer) {
          try { this._net = await this._ws("network"); } catch (e) { /* keep last */ }
        }
        if (this._me.manager) {
          const ur = await this._ws("users_list");
          this._users = ur.users; this._assignable = ur.assignable || [];
        }
        if (this._me.trainer) await this._trLoad();
        if ((this._top === "device" && !this._me.installer) || (this._top === "users" && !this._me.manager)) this._top = "hub";
        this._error = null;
      } catch (e) {
        this._error = e.message || String(e);
      }
      // never re-render while the user is typing in a form
      const sig = JSON.stringify(this._users) + (this._top === "train" ? JSON.stringify([this._tr.view, this._tr.model, [...this._tr.dsel], this._tr.filter, this._tr.lab, this._tr.data && this._tr.data.categories, this._tr.data && this._tr.data.train, this._tr.data && this._tr.data.busy, this._tr.data && this._tr.data.meta, this._tr.models]) : "");
      if (quiet && (this._top === "users" || this._top === "train") && sig === this._usig) return;
      this._usig = sig;
      const a = this.shadowRoot.activeElement;
      if (quiet && a && (a.tagName === "INPUT" || a.tagName === "SELECT")) return;
      this._render();
    }

    _build() {
      this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; height:100%; overflow:auto; background:var(--primary-background-color); color:var(--primary-text-color); font-family:var(--paper-font-body1_-_font-family, Roboto, sans-serif); }
        header { display:flex; align-items:center; gap:12px; padding:12px 16px; background:var(--app-header-background-color, var(--primary-color)); color:var(--app-header-text-color, #fff); position:sticky; top:0; z-index:2; }
        header h1 { font-size:20px; font-weight:500; margin:0; flex:1; }
        header ha-menu-button, header ha-icon-button { color: inherit; }
        nav { display:flex; gap:4px; padding:8px 12px; overflow-x:auto; background:var(--card-background-color); border-bottom:1px solid var(--divider-color); }
        nav button { background:none; border:0; padding:10px 16px; border-radius:20px; font-size:14px; color:var(--secondary-text-color); cursor:pointer; white-space:nowrap; position:relative; }
        nav button.on { background:var(--primary-color); color:#fff; }
        .badge { display:inline-block; min-width:18px; padding:0 6px; margin-left:6px; border-radius:9px; background:var(--error-color,#d33); color:#fff; font-size:12px; line-height:18px; text-align:center; }
        main { padding:16px; max-width:1100px; margin:0 auto; }
        .card { background:var(--card-background-color); border-radius:12px; padding:16px; margin-bottom:16px; box-shadow:var(--ha-card-box-shadow, 0 1px 3px rgba(0,0,0,.2)); }
        .card h2 { margin:0 0 12px; font-size:16px; font-weight:500; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; }
        .stat { text-align:center; padding:12px; border-radius:10px; background:var(--secondary-background-color); }
        .stat b { display:block; font-size:28px; }
        .stat span { color:var(--secondary-text-color); font-size:13px; }
        button.btn { background:var(--primary-color); color:#fff; border:0; border-radius:8px; padding:10px 18px; font-size:14px; cursor:pointer; }
        button.btn.big { font-size:18px; padding:18px 28px; }
        button.btn.stop { background:var(--error-color,#d33); }
        button.btn.ghost { background:transparent; color:var(--primary-color); border:1px solid var(--primary-color); }
        button.btn:disabled { opacity:.5; cursor:default; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        th,td { text-align:left; padding:8px 6px; border-bottom:1px solid var(--divider-color); vertical-align:middle; }
        th.sortable { cursor:pointer; user-select:none; white-space:nowrap; } th.sortable:hover { color:var(--primary-text-color); }
        tr.filters td { padding:4px 6px; } tr.filters input, tr.filters select { width:100%; }
        th { color:var(--secondary-text-color); font-weight:500; font-size:12px; text-transform:uppercase; }
        .pill { padding:2px 8px; border-radius:10px; font-size:12px; background:var(--secondary-background-color); }
        .ok { color:var(--success-color,#2a2); } .bad { color:var(--error-color,#d33); } .muted { color:var(--secondary-text-color); }
        .count { font-size:48px; font-weight:300; font-variant-numeric:tabular-nums; }
        input,select { font:inherit; padding:8px; border-radius:6px; border:1px solid var(--divider-color); background:var(--secondary-background-color); color:inherit; max-width:100%; box-sizing:border-box; }
        .row { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
        .field { margin:10px 0; display:flex; flex-direction:column; gap:4px; }
        .err { background:var(--error-color,#d33); color:#fff; padding:10px 14px; border-radius:8px; margin-bottom:12px; }
        .info { background:var(--secondary-background-color); padding:10px 14px; border-radius:8px; margin-bottom:12px; }
        @media (max-width:700px) {
          header { padding:8px 12px; } header h1 { font-size:18px; }
          nav { padding:6px 8px; gap:2px; -webkit-overflow-scrolling:touch; scrollbar-width:none; }
          nav button { padding:10px 14px; min-height:40px; }
          main { padding:8px; } .card { padding:12px; border-radius:10px; margin-bottom:10px; }
          .grid { grid-template-columns:repeat(2,1fr); gap:8px; } .stat b { font-size:22px; }
          input,select { font-size:16px; min-height:40px; } input[type=checkbox] { min-height:0; width:20px; height:20px; }
          button.btn { min-height:44px; padding:10px 14px; } button.btn.big { width:100%; font-size:16px; padding:14px; }
          .row { gap:8px; } .row > input:not([type=checkbox]), .row > select { flex:1 1 100%; width:100%; }
          .count { font-size:36px; }
          .card { overflow-wrap:anywhere; }
          .field input, .field select { width:100%; }
          table.dev, table.dev tbody, table.dev tr, table.dev td { display:block; width:100%; box-sizing:border-box; }
          table.dev tr.hd { display:none; }
          table.dev tr.filters { display:grid; grid-template-columns:1fr 1fr; gap:6px; padding:0 0 8px; border-bottom:1px solid var(--divider-color); }
          table.dev tr.filters td { padding:0; border:0; } table.dev tr.filters td:empty { display:none; }
          table.dev tr.filters td:first-child { grid-column:1/-1; }
          table.dev tbody tr { border:1px solid var(--divider-color); border-radius:10px; padding:8px 10px; margin:8px 0; background:var(--secondary-background-color); }
          table.dev tbody td { border:0; padding:4px 0; display:flex; justify-content:space-between; align-items:center; gap:10px; }
          table.dev tbody td[data-l]::before { content:attr(data-l); color:var(--secondary-text-color); font-size:12px; text-transform:uppercase; flex:none; }
          table.dev tbody td input, table.dev tbody td select { flex:1; min-width:0; width:auto; }
          table.dev tbody td.act { flex-wrap:wrap; justify-content:flex-start; } table.dev tbody td.act .btn { flex:1 1 30%; }
          table.dev tbody td.act { white-space:normal !important; }
          table.rs, table.rs tbody, table.rs tr, table.rs td { display:block; width:100%; box-sizing:border-box; }
          table.rs tr.hd { display:none; }
          table.rs tr { border-bottom:1px solid var(--divider-color); padding:6px 0; } table.rs td { border:0; padding:2px 0; }
          table.rs td .btn { margin:4px 6px 0 0; }
        }
      </style>
      <header><ha-menu-button></ha-menu-button><h1>Hub Mgmt</h1></header>
      <nav id="top"></nav><nav id="nav"></nav><main id="main"></main>`;
      const mb = this.shadowRoot.querySelector("ha-menu-button");
      if (mb) mb.hass = this._hass;
      this._built = true;
    }

    _esc(s) { return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])); }

    _render() {
      if (!this._built) return;
      const $ = (s) => this.shadowRoot.querySelector(s);
      const inst = !!(this._me && this._me.installer);
      const mgr = !!(this._me && this._me.manager);
      if (this._top === "device" && !inst) this._top = "hub";
      const trn = !!(this._me && this._me.trainer);
      if (this._top === "users" && !mgr) this._top = "hub";
      if (this._top === "train" && !trn) this._top = "hub";
      const top = $("#top");
      // Tabs are only built for roles that may use them
      if (inst || mgr || trn) {
        const n = this._flows.length + this._devices.filter((d) => d.new && !d.ignored).length;
        const tab = (k, l, badge) => `<button data-top="${k}" class="${this._top === k ? "on" : ""}">${l}${badge ? `<span class="badge">${badge}</span>` : ""}</button>`;
        top.style.display = "";
        top.innerHTML = tab("hub", "Hub Status") + (inst ? tab("device", "Device Mgmt", n) : "") + (mgr ? tab("users", "Users") : "") + (trn ? tab("train", "AINVR Training") : "");
        top.querySelectorAll("button").forEach((b) => (b.onclick = () => { this._top = b.dataset.top; this._msg = ""; this._render(); }));
      } else {
        top.style.display = "none"; top.innerHTML = "";
      }
      const nav = $("#nav");
      const main = $("#main");
      if (this._top === "train") {
        nav.style.display = "none"; nav.innerHTML = "";
        main.innerHTML = (this._error ? `<div class="err">${this._esc(this._error)}</div>` : "") + this._r_train();
        this._b_train(main);
        return;
      }
      if (this._top === "users") {
        nav.style.display = "none"; nav.innerHTML = "";
        main.innerHTML = (this._error ? `<div class="err">${this._esc(this._error)}</div>` : "") +
          (this._msg ? `<div class="info">${this._esc(this._msg)}</div>` : "") + this._r_users();
        this._b_users(main);
        return;
      }
      if (this._top === "hub") {
        nav.style.display = "none"; nav.innerHTML = "";
        main.innerHTML = (this._error ? `<div class="err">${this._esc(this._error)}</div>` : "") + this._r_hub();
        return;
      }
      nav.style.display = "";
      nav.innerHTML = TABS.map(([k, l]) => {
        const n = k === "discovered" ? this._flows.length : k === "devices" ? this._devices.filter((d) => d.new && !d.ignored).length : 0;
        return `<button data-tab="${k}" class="${k === this._tab ? "on" : ""}">${l}${n ? `<span class="badge">${n}</span>` : ""}</button>`;
      }).join("");
      nav.querySelectorAll("button").forEach((b) => (b.onclick = () => { this._tab = b.dataset.tab; this._msg = ""; this._render(); }));
      main.innerHTML = (this._error ? `<div class="err">${this._esc(this._error)}</div>` : "") +
        (this._msg ? `<div class="info">${this._esc(this._msg)}</div>` : "") + this[`_r_${this._tab}`]();
      this[`_b_${this._tab}`](main);
    }

    /* ---------- AINVR training (trainers and admins) ---------- */
    async _trLoad() {
      const t = this._tr;
      t.models = await this._ws("train_models");
      if (!t.model || !t.models.find((m) => m.name === t.model)) t.model = t.models[0] ? t.models[0].name : null;
      if (!t.model) { t.data = null; return; }
      if (this._top !== "train") return;
      t.data = await this._ws("train_data", { model: t.model });
      const want = [];
      if (t.view === "train") this._trList().forEach((f) => { if (!t.imgs["t/" + f]) want.push({ kind: "train", file: f }); });
      for (const [c, fs] of Object.entries(t.data.categories || {})) {
        const lim = t.view === "browse" ? (t.limit[c] || 24) : 12;
        fs.slice(0, lim).forEach((f) => { if (!t.imgs[`d/${c}/${f}`]) want.push({ kind: "dataset", category: c, file: f }); });
      }
      for (let i = 0; i < want.length; i += 40) {
        const part = want.slice(i, i + 40);
        const r = await this._ws("train_images", { model: t.model, items: part });
        part.forEach((it, j) => { t.imgs[it.kind === "train" ? "t/" + it.file : `d/${it.category}/${it.file}`] = r[j] || "-"; });
      }
    }
    _trPred(f) { const m = /^.*?-.*?-\d+(?:\.\d+)?-(.+)-([\d.]+)\.\w+$/.exec(f); return m ? { cat: m[1], score: parseFloat(m[2]) } : { cat: "(none)", score: null }; }
    _trList() {
      const t = this._tr;
      const all = (t.data && t.data.train) || [];
      return (t.filter ? all.filter((f) => this._trPred(f).cat === t.filter) : all).slice(0, 200);
    }
    _trZoom(keys, i) {
      const t = this._tr, root = this.shadowRoot;
      root.getElementById("trzoom")?.remove();
      const ov = document.createElement("div");
      ov.id = "trzoom";
      ov.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.88);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:#fff;font:14px sans-serif";
      let scale = 1;
      const show = () => {
        const k = keys[i], src = t.imgs[k];
        const name = k.split("/").slice(1).join(" / ");
        ov.innerHTML = `<div style="position:absolute;top:10px;left:16px;right:16px;display:flex;justify-content:space-between;align-items:center"><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${this._esc(name)} &nbsp; (${i + 1}/${keys.length})</span><span><button data-z="out" style="font-size:18px;padding:2px 10px">&minus;</button> <button data-z="in" style="font-size:18px;padding:2px 10px">+</button> <button data-z="x" style="font-size:18px;padding:2px 10px">&times;</button></span></div>
          <button data-z="prev" style="position:absolute;left:12px;top:50%;font-size:28px;padding:6px 12px" ${i ? "" : "disabled"}>&lsaquo;</button>
          <button data-z="next" style="position:absolute;right:12px;top:50%;font-size:28px;padding:6px 12px" ${i < keys.length - 1 ? "" : "disabled"}>&rsaquo;</button>
          <div style="max-width:92vw;max-height:86vh;overflow:auto">${src && src !== "-" ? `<img src="${src}" style="display:block;margin:auto;width:${Math.round(Math.min(92, 70 * scale))}vmin;max-width:none;image-rendering:auto;background:#222">` : "loading..."}</div>`;
        ov.querySelectorAll("button[data-z]").forEach((b) => (b.onclick = (e) => {
          e.stopPropagation();
          const a = b.dataset.z;
          if (a === "x") close(); else if (a === "prev" && i > 0) { i--; scale = 1; show(); } else if (a === "next" && i < keys.length - 1) { i++; scale = 1; show(); }
          else if (a === "in") { scale = Math.min(scale * 1.4, 4); show(); } else if (a === "out") { scale = Math.max(scale / 1.4, 0.5); show(); }
        }));
      };
      const key = (e) => { if (e.key === "Escape") close(); else if (e.key === "ArrowLeft" && i > 0) { i--; scale = 1; show(); } else if (e.key === "ArrowRight" && i < keys.length - 1) { i++; scale = 1; show(); } };
      const close = () => { document.removeEventListener("keydown", key); ov.remove(); };
      ov.onclick = (e) => { if (e.target === ov) close(); };
      document.addEventListener("keydown", key);
      root.appendChild(ov);
      show();
    }
    _trImg(src, size) {
      return `<div style="width:${size}px;height:${size}px;border-radius:6px;overflow:hidden;background:#000;flex:none;display:flex;align-items:center;justify-content:center">${src && src !== "-" ? `<img src="${src}" style="width:100%;height:100%;object-fit:contain;display:block">` : `<div class="muted" style="font-size:10px;text-align:center">loading...</div>`}</div>`;
    }

    _r_train() {
      const t = this._tr, d = t.data;
      if (!t.models.length) return `<div class="card"><h2>AINVR Training</h2><p class="muted">No custom classification models are configured in AINVR.</p></div>`;
      const cur = t.models.find((m) => m.name === t.model) || {};
      const grp = (ty, label) => {
        const ms = t.models.filter((m) => m.type === ty);
        return ms.length ? `<optgroup label="${label}">${ms.map((m) => `<option value="${this._esc(m.name)}" ${m.name === t.model ? "selected" : ""}>${this._esc(m.name)}</option>`).join("")}</optgroup>` : "";
      };
      const picker = `<select id="trm" style="font-weight:600;font-size:13px;padding:5px 8px;border-radius:6px;border:1px solid var(--divider-color);background:var(--card-background-color);color:inherit">${grp("object", "Object Models")}${grp("state", "State Models")}</select>`;
      const meta = (d && d.meta) || {};
      const busy = d && d.busy;

      const typeBadge = cur.type === "object"
        ? `<span class="pill" style="font-size:11px;font-weight:600;background:var(--secondary-background-color);color:var(--secondary-text-color)">Object</span>`
        : `<span class="pill" style="font-size:11px;font-weight:600;background:var(--secondary-background-color);color:var(--secondary-text-color)">State</span>`;

      const statusBadge = meta.has_trained
        ? `<span class="pill" style="font-size:11px;font-weight:600;color:var(--success-color,#2e7d32)">● Trained (${meta.last_training_image_count} imgs)</span>`
        : `<span class="pill" style="font-size:11px;font-weight:600;color:var(--warning-color,#ed6c02)">● Untrained</span>`;

      const metaDetail = cur.type === "object"
        ? `Target: <b>${this._esc((cur.objects || []).join(", ") || "-")}</b>`
        : `Cameras: <b>${this._esc((cur.cameras || []).join(", ") || "-")}</b>`;

      const navTab = (k, l, badge) => `<button class="btn ${t.view === k ? "" : "ghost"}" data-view="${k}" style="padding:5px 12px;font-size:12px;border-radius:6px">${l}${badge ? ` <span class="badge" style="background:${t.view === k ? '#fff' : 'var(--primary-color)'};color:${t.view === k ? 'var(--primary-color)' : '#fff'}">${badge}</span>` : ""}</button>`;

      const header = `${t.msg ? `<div class="info" style="border-left:4px solid var(--primary-color);margin-bottom:10px;padding:8px 12px;font-size:13px">${this._esc(t.msg)}</div>` : ""}
        <div class="card" style="margin-bottom:10px;padding:10px 14px;border:1px solid var(--divider-color)">
          <div class="row" style="justify-content:space-between;align-items:center;gap:10px">
            <div class="row" style="gap:8px;align-items:center">
              <span style="font-size:11px;font-weight:700;color:var(--secondary-text-color);text-transform:uppercase">Model:</span>
              ${picker}
              ${typeBadge}
              ${statusBadge}
              <span class="muted" style="font-size:12px">${metaDetail}</span>
              ${meta.dataset_changed ? '<span class="pill" style="font-size:11px;color:var(--warning-color,#ed6c02);font-weight:bold">Pending changes</span>' : ""}
            </div>
            <button class="btn" id="trgo" style="padding:6px 14px;font-size:13px" ${busy || !d || !Object.keys(d.categories).length ? "disabled" : ""}>
              ${busy ? "Training in progress..." : "Train Model"}
            </button>
          </div>
          <div class="row" style="margin-top:8px;gap:6px;border-top:1px solid var(--divider-color);padding-top:8px">
            ${navTab("train", "Unlabelled Queue", d && d.train.length ? d.train.length : 0)}
            ${navTab("browse", "Categories & Dataset", d ? Object.keys(d.categories).length + " classes" : "")}
            ${cur.type === "object" ? navTab("upload", "Upload Images", "") : ""}
          </div>
        </div>`;

      if (!d) return header + `<div class="card muted" style="padding:20px;text-align:center">Loading data for ${this._esc(cur.name || "model")}...</div>`;
      if (t.view === "browse") return header + this._r_trBrowse();
      if (t.view === "upload" && cur.type === "object") return header + this._r_trUpload();
      return header + this._r_trWork();
    }

    _r_trBrowse() {
      const t = this._tr, d = t.data;
      t.dsel.forEach((k) => { const i = k.indexOf("/"); if (!(d.categories[k.slice(0, i)] || []).includes(k.slice(i + 1))) t.dsel.delete(k); });

      const cats = Object.entries(d.categories).map(([c, fs]) => {
        const lim = t.limit[c] || 24;
        return `<div style="margin-bottom:12px;background:var(--secondary-background-color);border-radius:8px;padding:8px 10px;border:1px solid var(--divider-color)">
          <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:6px">
            <div class="row" style="gap:8px;align-items:center">
              <b style="font-size:13px">${this._esc(c)}</b>
              <span class="pill" style="background:var(--card-background-color);font-weight:bold;color:var(--primary-color);font-size:11px">${fs.length} images</span>
            </div>
            <div class="row" style="gap:6px">
              <button class="btn ghost" data-rc="${this._esc(c)}" style="padding:3px 8px;font-size:11px">Rename</button>
              <button class="btn ghost" data-dall="${this._esc(c)}" style="padding:3px 8px;font-size:11px">Select all</button>
            </div>
          </div>
          <div class="row" style="gap:6px;align-items:flex-start">
            ${fs.slice(0, lim).map((f) => {
              const k = c + "/" + f, on = t.dsel.has(k);
              return `<label style="position:relative;cursor:pointer;border:2px solid ${on ? "var(--error-color,#d33)" : "transparent"};border-radius:6px;display:block">
                ${this._trImg(t.imgs[`d/${c}/${f}`], 130)}
                <input type="checkbox" data-ds="${this._esc(k)}" ${on ? "checked" : ""} style="position:absolute;top:3px;left:3px;accent-color:var(--error-color,#d33);cursor:pointer;width:16px;height:16px">
                <button type="button" data-zoom="d/${this._esc(c)}/${this._esc(f)}" title="Open larger preview" style="position:absolute;top:3px;right:3px;width:22px;height:22px;padding:0;border:none;border-radius:4px;background:rgba(0,0,0,.6);color:#fff;font-size:14px;line-height:22px;cursor:zoom-in;z-index:2">&#x2922;</button>
              </label>`;
            }).join("")}
            ${fs.length > lim ? `<button class="btn ghost" data-more="${this._esc(c)}" style="align-self:center;margin-left:6px;font-size:11px;padding:5px 8px">+${fs.length - lim} more</button>` : ""}
          </div>
        </div>`;
      }).join("");

      return `<div class="card" style="border:1px solid var(--divider-color);padding:12px">
        <div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px;border-bottom:1px solid var(--divider-color);padding-bottom:8px">
          <div class="row" style="gap:8px;align-items:center">
            <h2 style="margin:0;font-size:14px">${this._esc(t.model)} Classes</h2>
            <span class="muted" style="font-size:12px">(${Object.keys(d.categories).length} categories)</span>
          </div>
          <form id="trnew" class="row" style="gap:6px">
            <input name="c" placeholder="New category" required maxlength="40" style="padding:4px 8px;font-size:12px">
            <button class="btn" type="submit" style="padding:4px 10px;font-size:12px">+ Add Class</button>
          </form>
        </div>
        <div class="row" style="margin-bottom:10px;position:sticky;top:0;z-index:1;background:var(--card-background-color);padding:6px 0;border-bottom:1px solid var(--divider-color);justify-content:space-between;align-items:center">
          <span style="font-size:12px;font-weight:600;color:var(--secondary-text-color)">${t.dsel.size ? `Selected: ${t.dsel.size} image(s)` : "Select images to remove or retrain:"}</span>
          <div class="row" style="gap:6px">
            <button class="btn ghost stop" id="dsrm" style="padding:4px 10px;font-size:12px" ${t.dsel.size ? "" : "disabled"}>Remove</button>
            <button class="btn stop" id="dsrt" style="padding:4px 10px;font-size:12px" ${t.dsel.size && !(d.busy) ? "" : "disabled"}>Remove &amp; Retrain</button>
            <button class="btn ghost" id="dsno" style="padding:4px 10px;font-size:12px" ${t.dsel.size ? "" : "disabled"}>Clear</button>
          </div>
        </div>
        ${cats || '<p class="muted" style="padding:16px 0;text-align:center">No categories created yet.</p>'}
      </div>`;
    }

    _r_trWork() {
      const t = this._tr, d = t.data;
      const cats = Object.keys(d.categories);
      const preds = {};
      d.train.forEach((f) => { const p = this._trPred(f).cat; preds[p] = (preds[p] || 0) + 1; });
      cats.forEach((c) => { if (!(c in preds)) preds[c] = 0; });
      if (t.filter && !(t.filter in preds)) preds[t.filter] = 0;
      t.sel.forEach((f) => { if (!d.train.includes(f)) t.sel.delete(f); });
      const shown = this._trList();

      const filtOpts = `<option value="">All Guesses (${d.train.length})</option>` + Object.keys(preds).sort().map((p) => `<option value="${this._esc(p)}" ${p === t.filter ? "selected" : ""}>Guess: ${this._esc(p)} (${preds[p]})</option>`).join("");

      // Rapid one-click category buttons - no redundant dropdown needed!
      const quickBtns = cats.map((c) => `<button class="btn" data-quicklab="${this._esc(c)}" style="padding:4px 10px;font-size:12px;border-radius:4px" ${t.sel.size ? "" : "disabled"}>Label as ${this._esc(c)}</button>`).join("");

      const un = shown.map((f) => {
        const info = this._trPred(f);
        const on = t.sel.has(f);
        const scorePct = info.score !== null ? Math.round(info.score * 100) + "%" : "";
        const scoreBadge = info.score !== null
          ? `<span style="font-size:10px;font-weight:700;padding:1px 4px;border-radius:4px;background:${info.score >= 0.8 ? 'rgba(var(--rgb-success-color, 46, 125, 50), 0.2)' : 'rgba(var(--rgb-warning-color, 237, 108, 2), 0.2)'};color:${info.score >= 0.8 ? 'var(--success-color, #2e7d32)' : 'var(--warning-color, #ed6c02)'}">${scorePct}</span>`
          : "";

        return `<label style="width:200px;border:2px solid ${on ? "var(--primary-color)" : "transparent"};border-radius:6px;overflow:hidden;background:var(--secondary-background-color);position:relative;cursor:pointer;display:flex;flex-direction:column;box-shadow:0 1px 3px rgba(0,0,0,0.1)">
          <div style="height:170px;position:relative;background:#000">
            ${t.imgs["t/" + f] && t.imgs["t/" + f] !== "-" ? `<img src="${t.imgs["t/" + f]}" style="width:100%;height:100%;object-fit:contain;display:block">` : '<div class="muted" style="padding:30px 4px;font-size:10px;text-align:center">loading...</div>'}
            <input type="checkbox" data-sel="${this._esc(f)}" ${on ? "checked" : ""} style="position:absolute;top:3px;left:3px;accent-color:var(--primary-color);width:16px;height:16px;cursor:pointer">
            <button type="button" data-zoom="t/${this._esc(f)}" title="Open larger preview" style="position:absolute;top:3px;right:3px;width:22px;height:22px;padding:0;border:none;border-radius:4px;background:rgba(0,0,0,.6);color:#fff;font-size:14px;line-height:22px;cursor:zoom-in;z-index:2">&#x2922;</button>
          </div>
          <div style="padding:3px 5px;background:var(--card-background-color);border-top:1px solid var(--divider-color);display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:10px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px">${this._esc(info.cat)}</span>
            ${scoreBadge}
          </div>
        </label>`;
      }).join("");

      return `<div class="card" style="border:1px solid var(--divider-color);padding:10px 14px">
        <div class="row" style="justify-content:space-between;align-items:center;background:var(--secondary-background-color);padding:6px 10px;border-radius:6px;border:1px solid var(--divider-color)">
          <div class="row" style="gap:6px;align-items:center">
            <span style="font-size:11px;font-weight:600;color:var(--secondary-text-color)">Filter:</span>
            <select id="trf" style="font-size:12px;padding:3px 6px">${filtOpts}</select>
            <button class="btn ghost" id="trall" style="padding:3px 8px;font-size:11px">Select All Shown (${shown.length})</button>
            <button class="btn ghost" id="trnone" style="padding:3px 8px;font-size:11px">Clear</button>
          </div>
          <div class="row" style="gap:6px;align-items:center">
            <span style="font-size:12px;font-weight:bold;color:var(--primary-color)">${t.sel.size} Selected</span>
            <button class="btn ghost stop" id="trdis" style="padding:3px 8px;font-size:11px" ${t.sel.size ? "" : "disabled"}>Discard</button>
          </div>
        </div>

        <div class="row" style="margin:8px 0;align-items:center;gap:6px">
          <span style="font-size:12px;font-weight:600">Quick label selected:</span>
          <div class="row" style="gap:4px;flex-wrap:wrap">${quickBtns}</div>
        </div>

        <div class="row" style="gap:8px;align-items:flex-start;margin-top:6px">
          ${un || `<div class="muted" style="padding:24px 0;width:100%;text-align:center">${t.filter ? `No unlabelled images matching "${this._esc(t.filter)}".` : "Queue is empty. Everything is labelled!"}</div>`}
        </div>
      </div>`;
    }

    _r_trUpload() {
      const t = this._tr, d = t.data;
      const cats = Object.keys(d.categories);
      const catOpts = cats.map((c) => `<option>${this._esc(c)}</option>`).join("");
      return `<div class="card" style="border:1px solid var(--divider-color);padding:14px">
        <h2 style="font-size:14px;margin-bottom:6px">Upload Training Images</h2>
        <p class="muted" style="font-size:12px;margin-bottom:12px">Upload photos directly into a dataset class for <b>${this._esc(t.model)}</b>. Photos are resized to 1024px before saving.</p>
        
        <div style="background:var(--secondary-background-color);border:2px dashed var(--divider-color);border-radius:6px;padding:16px;text-align:center">
          <div class="row" style="justify-content:center;gap:10px;align-items:center">
            <div class="field" style="margin:0"><label style="font-size:11px;font-weight:600">Category</label><select id="upc" style="padding:5px 8px;font-size:12px">${catOpts}</select></div>
            <div class="field" style="margin:0"><label style="font-size:11px;font-weight:600">Select Files (max 20)</label><input type="file" id="upf" accept="image/*" multiple style="background:var(--card-background-color);padding:4px;font-size:12px"></div>
            <button class="btn" id="upgo" style="padding:6px 14px;font-size:12px" ${cats.length ? "" : "disabled"}>Upload</button>
          </div>
          <div class="row" id="upprev" style="gap:6px;justify-content:center;margin-top:10px"></div>
          <div class="muted" id="upres" style="margin-top:6px;font-size:11px"></div>
        </div>
      </div>`;
    }

    async _trShrink(file) {
      const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
      const k = Math.min(1, 1024 / Math.max(bmp.width, bmp.height));
      const c = document.createElement("canvas");
      c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
      c.getContext("2d").drawImage(bmp, 0, 0, c.width, c.height);
      return c.toDataURL("image/jpeg", 0.92);
    }

    _b_train(m) {
      const t = this._tr;
      const act = async (fn, ok) => {
        try { await fn(); if (ok !== undefined) t.msg = ok; } catch (e) { t.msg = "Failed: " + (e.message || e); }
        t.sel = new Set(); this._usig = ""; await this._refresh();
      };
      const reset = () => { t.dsel = new Set(); t.filter = ""; t.lab = ""; t.data = null; t.sel = new Set(); t.imgs = {}; t.limit = {}; this._usig = ""; };
      m.querySelectorAll("button[data-view]").forEach((b) => (b.onclick = () => { t.view = b.dataset.view; t.msg = ""; reset(); this._render(); this._refresh(); }));
      const zl = [...m.querySelectorAll("button[data-zoom]")].map((z) => z.dataset.zoom);
      m.querySelectorAll("button[data-zoom]").forEach((z) => (z.onclick = (e) => { e.preventDefault(); e.stopPropagation(); this._trZoom(zl, zl.indexOf(z.dataset.zoom)); }));
      m.querySelectorAll("button[data-more]").forEach((b) => (b.onclick = () => { t.limit[b.dataset.more] = (t.limit[b.dataset.more] || 24) + 48; this._usig = ""; this._refresh(); }));
      m.querySelectorAll("input[data-ds]").forEach((c) => (c.onchange = () => { c.checked ? t.dsel.add(c.dataset.ds) : t.dsel.delete(c.dataset.ds); this._usig = ""; this._render(); }));
      m.querySelectorAll("button[data-dall]").forEach((b) => (b.onclick = () => { const c = b.dataset.dall; (t.data.categories[c] || []).slice(0, t.limit[c] || 24).forEach((f) => t.dsel.add(c + "/" + f)); this._usig = ""; this._render(); }));
      m.querySelector("#dsno")?.addEventListener("click", () => { t.dsel = new Set(); this._usig = ""; this._render(); });

      const rmSel = async () => {
        const by = {};
        t.dsel.forEach((k) => { const i = k.indexOf("/"); (by[k.slice(0, i)] = by[k.slice(0, i)] || []).push(k.slice(i + 1)); });
        for (const [c, fs] of Object.entries(by)) for (let i = 0; i < fs.length; i += 100) await this._ws("train_dataset_delete", { model: t.model, category: c, files: fs.slice(i, i + 100) });
        const n = t.dsel.size; t.dsel = new Set(); t.imgs = {};
        return n;
      };
      const warn = () => {
        const by = {}; t.dsel.forEach((k) => { const c = k.slice(0, k.indexOf("/")); by[c] = (by[c] || 0) + 1; });
        const empties = Object.keys(by).filter((c) => c.toLowerCase() !== "none" && by[c] >= ((t.data.categories[c] || []).length));
        return `Permanently delete ${t.dsel.size} image(s) from "${t.model}"?` + (empties.length ? `\n\nThis empties ${empties.join(", ")}, which removes the category.` : "");
      };

      const rm = m.querySelector("#dsrm");
      if (rm) rm.onclick = () => { if (confirm(warn())) act(async () => { const n = await rmSel(); t.msg = `Removed ${n} image(s). Train the model to apply the change.`; }); };
      const rt = m.querySelector("#dsrt");
      if (rt) rt.onclick = () => { if (confirm(warn() + `\n\nThen retrain now? Training uses the hub for several minutes and replaces the live model when done.`)) act(async () => { const n = await rmSel(); await this._ws("train_start", { model: t.model }); t.msg = `Removed ${n} image(s). Training started.`; }); };
      const sel = m.querySelector("#trm");
      if (sel) sel.onchange = () => { t.model = sel.value; reset(); this._render(); this._refresh(); };
      m.querySelectorAll("input[data-sel]").forEach((c) => (c.onchange = () => { c.checked ? t.sel.add(c.dataset.sel) : t.sel.delete(c.dataset.sel); this._usig = ""; this._render(); }));
      const files = () => [...t.sel];
      const trf = m.querySelector("#trf");
      if (trf) trf.onchange = () => { t.filter = trf.value; t.sel = new Set(); this._usig = ""; this._render(); this._refresh(); };

      m.querySelectorAll("button[data-quicklab]").forEach((b) => (b.onclick = () => {
        const c = b.dataset.quicklab; const n = t.sel.size;
        act(async () => { for (const f of files()) await this._ws("train_categorize", { model: t.model, file: f, category: c }); }, `Labelled ${n} image(s) as "${c}".`);
      }));

      const dis = m.querySelector("#trdis");
      if (dis) dis.onclick = () => { if (confirm(`Delete ${t.sel.size} image(s)?`)) act(() => this._ws("train_discard", { model: t.model, files: files() }), "Discarded."); };
      m.querySelector("#trall")?.addEventListener("click", () => { this._trList().forEach((f) => t.sel.add(f)); this._usig = ""; this._render(); });
      m.querySelector("#trnone")?.addEventListener("click", () => { t.sel = new Set(); this._usig = ""; this._render(); });
      const nf = m.querySelector("#trnew");
      if (nf) nf.onsubmit = (e) => { e.preventDefault(); const c = nf.elements.c.value.trim(); act(() => this._ws("train_category", { model: t.model, action: "create", category: c }), `Category "${c}" added.`); };
      m.querySelectorAll("button[data-rc]").forEach((b) => (b.onclick = () => { const n = prompt(`Rename category "${b.dataset.rc}" to:`, b.dataset.rc); if (n && n !== b.dataset.rc) { t.imgs = {}; act(() => this._ws("train_category", { model: t.model, action: "rename", category: b.dataset.rc, new_category: n.trim() }), "Renamed."); } }));
      const go = m.querySelector("#trgo");
      if (go) go.onclick = () => { if (confirm(`Train "${t.model}" now? It uses the hub's GPU/CPU for several minutes and replaces the live model when done.`)) act(() => this._ws("train_start", { model: t.model }), "Training started."); };

      const upf = m.querySelector("#upf"), prev = m.querySelector("#upprev"), res = m.querySelector("#upres"), upgo = m.querySelector("#upgo");
      if (upf) {
        upf.onchange = () => {
          prev.innerHTML = "";
          [...upf.files].slice(0, 20).forEach((f) => { const im = document.createElement("img"); im.src = URL.createObjectURL(f); im.style.cssText = "width:60px;height:60px;object-fit:cover;border-radius:6px;border:1px solid var(--divider-color)"; prev.appendChild(im); });
          res.textContent = upf.files.length > 20 ? "Only the first 20 images will be uploaded." : "";
        };
        upgo.onclick = async () => {
          const cat = m.querySelector("#upc").value, fl = [...upf.files].slice(0, 20);
          if (!fl.length) { res.textContent = "Choose at least one image."; return; }
          upgo.disabled = true; let ok = 0; const bad = [];
          for (let i = 0; i < fl.length; i++) {
            res.textContent = `Uploading ${i + 1} of ${fl.length}...`;
            try { await this._ws("train_upload", { model: t.model, category: cat, images: [await this._trShrink(fl[i])] }); ok++; }
            catch (e) { bad.push(`${fl[i].name}: ${e.message || e}`); }
          }
          t.msg = `Uploaded ${ok} of ${fl.length} image(s) to ${cat}.` + (bad.length ? " Failed: " + bad.join("; ") : "");
          t.imgs = {}; this._usig = ""; await this._refresh();
        };
      }
    }

    _roleLabel(r) {
      return ({ admin: "Admin", installer: "Installer", homeowner: "Home Owner", manager: "Manager", operator: "Operator", viewer: "Viewer", user: "No app role" })[r] || r;
    }

    /* ---------- users (homeowners and admins) ---------- */
    _r_users() {
      const rows = this._users.map((u) => `<tr>
        <td>${this._esc(u.name)}</td><td class="muted">${this._esc(u.username || "-")}</td>
        <td>${u.assignable ? `<select data-role="${u.id}">${["user", ...this._assignable].map((r) => `<option value="${r}" ${r === u.role ? "selected" : ""}>${this._roleLabel(r)}</option>`).join("")}</select>` : `<span class="pill">${this._esc(this._roleLabel(u.role))}</span>`}</td>
        <td style="white-space:nowrap">${u.resettable ? `<button class="btn ghost" data-pw="${u.id}">Reset password</button> ` : ""}${u.removable ? `<button class="btn ghost stop" data-ru="${u.id}">Remove</button>` : ""}</td></tr>`).join("");
      const ru = this._reset && this._users.find((x) => x.id === this._reset);
      const resetCard = ru ? `<div class="card"><h2>Reset password for ${this._esc(ru.name)}</h2>
        <form id="pf" autocomplete="off"><div class="row">
          <div class="field"><label>New password (min 8)</label><input name="p1" type="password" required minlength="8" autocomplete="new-password"></div>
          <div class="field"><label>Repeat password</label><input name="p2" type="password" required minlength="8" autocomplete="new-password"></div>
        </div><div class="row"><button class="btn" type="submit">Set password</button><button class="btn ghost" type="button" id="pc">Cancel</button></div></form></div>` : "";
      return resetCard + `<div class="card"><h2>Add a user</h2>
        <p class="muted">New users are never Sentinel Hub administrators. The role decides what they can do here and in the Sentinel Link app API: <b>Installer</b> manages devices, <b>Home Owner</b> manages users, <b>Manager / Operator / Viewer</b> are app access levels. Role changes apply to the app API immediately.</p>
        <form id="uf" autocomplete="off">
          <div class="row">
            <div class="field"><label>Name</label><input name="name" required maxlength="60"></div>
            <div class="field"><label>Username</label><input name="username" required pattern="[A-Za-z0-9._\\-]{3,32}" title="3-32 letters, digits, . _ -" autocapitalize="none"></div>
            <div class="field"><label>Password (min 8)</label><input name="password" type="password" required minlength="8" autocomplete="new-password"></div>
            <div class="field"><label>Repeat password</label><input name="password2" type="password" required minlength="8" autocomplete="new-password"></div>
            <div class="field"><label>Role</label><select name="role">${["user", ...this._assignable].map((r) => `<option value="${r}">${this._roleLabel(r)}</option>`).join("")}</select></div>
          </div>
          <button class="btn" type="submit">Add user</button>
        </form></div>
      <div class="card"><h2>Users (${this._users.length})</h2><table class="rs">
        <tr class="hd"><th>Name</th><th>Username</th><th>Role</th><th></th></tr>${rows}</table></div>`;
    }
    _b_users(m) {
      const f = m.querySelector("#uf");
      if (f) f.onsubmit = async (e) => {
        e.preventDefault();
        const v = (n) => f.elements[n].value;
        if (v("password") !== v("password2")) { this._msg = "Passwords do not match."; this._render(); return; }
        try {
          await this._ws("user_create", { name: v("name"), username: v("username"), password: v("password"), role: v("role") });
          this._msg = `User "${v("name")}" added.`;
        } catch (err) { this._msg = "Could not add user: " + (err.message || err); }
        f.reset();
        this._usig = "";
        this._refresh();
      };
      m.querySelectorAll("select[data-role]").forEach((sel) => (sel.onchange = async () => {
        const u = this._users.find((x) => x.id === sel.dataset.role); if (!u) return;
        try { await this._ws("user_set_role", { user_id: u.id, role: sel.value }); this._msg = `"${u.name}" is now ${this._roleLabel(sel.value)}.`; }
        catch (err) { this._msg = "Could not change role: " + (err.message || err); }
        this._usig = ""; this._refresh();
      }));
      m.querySelectorAll("button[data-pw]").forEach((b) => (b.onclick = () => { this._reset = b.dataset.pw; this._msg = ""; this._usig = ""; this._render(); }));
      m.querySelector("#pc")?.addEventListener("click", () => { this._reset = null; this._render(); });
      const pf = m.querySelector("#pf");
      if (pf) pf.onsubmit = async (e) => {
        e.preventDefault();
        const u = this._users.find((x) => x.id === this._reset); if (!u) return;
        if (pf.elements.p1.value !== pf.elements.p2.value) { this._msg = "Passwords do not match."; this._render(); return; }
        try { await this._ws("user_password", { user_id: u.id, password: pf.elements.p1.value }); this._msg = `Password for "${u.name}" changed.`; this._reset = null; }
        catch (err) { this._msg = "Could not change password: " + (err.message || err); }
        this._usig = "";
        this._refresh();
      };
      m.querySelectorAll("button[data-ru]").forEach((b) => (b.onclick = async () => {
        const u = this._users.find((x) => x.id === b.dataset.ru); if (!u) return;
        if (!confirm(`Remove user "${u.name}"? They will no longer be able to sign in.`)) return;
        try { await this._ws("user_remove", { user_id: u.id }); this._msg = `User "${u.name}" removed.`; } catch (err) { this._msg = "Remove failed: " + (err.message || err); }
        this._usig = "";
        this._refresh();
      }));
    }

    /* ---------- hub status (all users) ---------- */
    _dur(sec) {
      if (sec == null) return "-";
      const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
      return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
    }

    _r_net() {
      const n = this._net;
      if (!n) return "";
      const copy = (t) => `<code>${this._esc(t)}</code>`;
      const row = (k, v) => `<tr><td class="muted">${k}</td><td>${v}</td></tr>`;
      const ts = n.tailscale || {};
      const tsok = ts.state === "Running";
      const url = (h) => `<a href="${this._esc(h)}" target="_blank" rel="noopener">${this._esc(h)}</a>`;
      const loc = (n.local || []).map((l) => row(`Local (${this._esc(l.iface)})`, `${copy(l.ip)} &nbsp; ${url("http://" + l.ip + ":8123")}`)).join("");
      return `<div class="card"><h2>Network</h2><table><tbody>
        ${loc || row("Local IP", "-")}
        ${row("Public IP", n.public ? copy(n.public) : '<span class="muted">unavailable (offline?)</span>')}
        ${row("Tailscale", ts.state === "unavailable" ? '<span class="muted">unavailable (socket not mounted)</span>' : `<b class="${tsok ? "ok" : "bad"}">${this._esc(ts.state || "?")}</b>${ts.tailnet ? " &nbsp;<span class=\"muted\">" + this._esc(ts.tailnet) + "</span>" : ""}`)}
        ${ts.ipv4 ? row("Tailscale IP", `${copy(ts.ipv4)} &nbsp; ${url("http://" + ts.ipv4 + ":8123")}`) : ""}
        ${ts.dns ? row("Tailscale name", copy(ts.dns)) : ""}
        ${ts.ipv6 ? row("Tailscale IPv6", copy(ts.ipv6)) : ""}
        ${ts.peers != null && ts.state === "Running" ? row("Tailnet peers", ts.peers) : ""}
      </tbody></table></div>`;
    }
    _r_hub() {
      const h = this._hub || {};
      const pct = (v, warn) => (v == null ? "-" : `<b class="${v >= warn ? "bad" : ""}">${v}%</b>`);
      const zig = h.zigbee_state === "online";
      return this._r_net() + `<div class="card"><h2>Software</h2><div class="grid">
        <div class="stat"><b style="font-size:20px">${this._esc(h.os_version || "-")}</b><span>Operating system</span></div>
        <div class="stat"><b style="font-size:20px">Sentinel Hub core ${this._esc(h.ha_version || "-")}</b><span>Core</span></div>
      </div></div>
      <div class="card"><h2>${this._esc(h.name || "Hub")}</h2><div class="grid">
        <div class="stat"><b>${this._dur(h.uptime_s)}</b><span>Uptime</span></div>
        <div class="stat">${pct(h.mem_used_pct, 90)}<span>Memory${h.mem_total_mb ? " of " + Math.round(h.mem_total_mb / 1024 * 10) / 10 + " GB" : ""}</span></div>
        <div class="stat">${pct(h.disk_used_pct, 90)}<span>Disk${h.disk_free_gb != null ? " (" + h.disk_free_gb + " GB free)" : ""}</span></div>
        <div class="stat"><b>${h.load1 ?? "-"}</b><span>Load (1 min)</span></div>
      </div></div>
      <div class="card"><h2>Services</h2><div class="grid">
        <div class="stat"><b class="${zig ? "ok" : "bad"}">${zig ? "Online" : this._esc(h.zigbee_state || "?")}</b><span>Zigbee</span></div>
        <div class="stat"><b class="${h.matter_ready ? "ok" : "bad"}">${h.matter_ready ? "Ready" : "Down"}</b><span>Matter</span></div>
        <div class="stat"><b>${h.zigbee_devices ?? 0}</b><span>Zigbee devices</span></div>
        <div class="stat"><b>${h.matter_devices ?? 0}</b><span>Matter devices</span></div>
        <div class="stat"><b>${h.entities ?? 0}</b><span>Entities</span></div>
        <div class="stat"><b class="${h.unavailable ? "bad" : ""}">${h.unavailable ?? 0}</b><span>Unavailable</span></div>
      </div></div>`;
    }

    /* ---------- overview ---------- */
    _r_overview() {
      const s = this._status, d = this._devices;
      const by = (p) => d.filter((x) => x.protocol === p).length;
      const online = s.bridge_state === "online";
      return `<div class="card"><h2>System</h2><div class="grid">
        <div class="stat"><b class="${online ? "ok" : "bad"}">${online ? "Online" : this._esc(s.bridge_state || "?")}</b><span>Zigbee2MQTT</span></div>
        <div class="stat"><b class="${s.matter_ready ? "ok" : "bad"}">${s.matter_ready ? "Ready" : "Down"}</b><span>Matter server</span></div>
        <div class="stat"><b>${by("zigbee")}</b><span>Zigbee devices</span></div>
        <div class="stat"><b>${by("matter")}</b><span>Matter devices</span></div>
        <div class="stat"><b class="${this._flows.length ? "bad" : ""}">${this._flows.length}</b><span>Awaiting setup</span></div>
        <div class="stat"><b class="${d.filter((x) => !x.available).length ? "bad" : ""}">${d.filter((x) => !x.available).length}</b><span>Unavailable</span></div>
      </div></div>
      <div class="card"><h2>Coordinator</h2><div class="muted">${s.coordinator ? this._esc(`${s.coordinator.type || ""} ${s.coordinator.meta?.revision || ""}`) : "-"} &middot; Zigbee2MQTT ${this._esc(s.z2m_version || "-")}</div></div>`;
    }
    _b_overview() {}

    /* ---------- pairing ---------- */
    _r_pairing() {
      const s = this._status, rem = s.permit_join_remaining || 0, open = rem > 0;
      const ev = (s.events || []).map((e) => `<tr><td>${new Date(e.t * 1000).toLocaleTimeString()}</td><td>${this._esc(e.type.replace("device_", ""))}</td><td>${this._esc(e.name)}</td><td>${this._esc(e.status || e.model || "")}${e.supported === false ? ' <span class="bad">unsupported</span>' : ""}</td></tr>`).join("");
      return `<div class="card"><h2>Zigbee pairing</h2>
        <div class="row">
          ${open ? `<div class="count">${rem}s</div><button class="btn big stop" id="pj-stop">Stop pairing</button>`
                 : `<button class="btn big" id="pj-start" ${s.bridge_state === "online" ? "" : "disabled"}>Enable pairing (4 min)</button>`}
        </div>
        <p class="muted">Put the device in pairing mode (usually factory reset: hold the button or power-cycle 5-6 times) within 1 m of the hub. It will appear below and under Devices. Pairing closes automatically.</p>
        <table class="rs"><tr class="hd"><th>Time</th><th>Event</th><th>Device</th><th>Status</th></tr>${ev || '<tr><td colspan="4" class="muted">No events yet</td></tr>'}</table></div>
      <div class="card"><h2>Matter</h2>
        <p class="muted">Enter the setup code printed on the device or its QR payload (starts with MT:). The device must be in pairing mode and on the same network.</p>
        <div class="row"><input id="mcode" placeholder="Matter setup code" size="34" autocomplete="off" ${this._busy ? "disabled" : ""}>
        <button class="btn" id="mgo" ${this._busy || !s.matter_ready ? "disabled" : ""}>${this._busy ? "Commissioning..." : "Commission"}</button></div></div>`;
    }
    _b_pairing(m) {
      const go = async (time) => { try { await this._ws("zigbee_permit", { time }); await new Promise((r) => setTimeout(r, 600)); } catch (e) { this._msg = e.message; } this._refresh(); };
      m.querySelector("#pj-start")?.addEventListener("click", () => go(240));
      m.querySelector("#pj-stop")?.addEventListener("click", () => go(0));
      m.querySelector("#mgo")?.addEventListener("click", async () => {
        const code = m.querySelector("#mcode").value.trim();
        if (!code) return;
        this._busy = true; this._msg = ""; this._render();
        try { await this._ws("matter_commission", { code }); this._msg = "Matter device commissioned. Find it under Devices."; }
        catch (e) { this._msg = "Commissioning failed: " + (e.message || e); }
        this._busy = false; this._refresh();
      });
    }

    /* ---------- devices ---------- */
    _cols() {
      return [
        ["name", "Name"], ["protocol", "Type"], ["model", "Model"],
        ["area", "Area"], ["state", "State"], ["info", "Info"],
      ];
    }
    _val(d, k) {
      if (k === "model") return [d.manufacturer, d.model].filter(Boolean).join(" ");
      if (k === "state") return d.available ? "online" : "offline";
      if (k === "info") return d.battery != null ? d.battery : d.linkquality != null ? d.linkquality : -1;
      if (k === "name") return (this._edits[d.id]?.name ?? d.name) || "";
      return d[k] ?? "";
    }
    _visible() {
      const f = this._f, q = (x) => String(x || "").toLowerCase();
      let rows = this._devices.filter((d) =>
        (!f.name || q(this._val(d, "name")).includes(q(f.name))) &&
        (!f.model || q(this._val(d, "model")).includes(q(f.model))) &&
        (!f.protocol || d.protocol === f.protocol) &&
        (!f.area || (f.area === "__none" ? !d.area_id : d.area_id === f.area)) &&
        (!f.state || this._val(d, "state") === f.state) &&
        (!f.newOnly || d.new) &&
        (!f.unusedOnly || !d.available) &&
        (f.showIgnored || !d.ignored));
      const { key, dir } = this._sort;
      if (key) {
        rows = rows.slice().sort((a, b) => {
          const x = this._val(a, key), y = this._val(b, key);
          const c = typeof x === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true, sensitivity: "base" });
          return c * dir;
        });
      }
      return rows;
    }
    _rows() {
      const opts = (sel) => `<option value="">- none -</option>` + this._areas.map((a) => `<option value="${a.id}" ${a.id === sel ? "selected" : ""}>${this._esc(a.name)}</option>`).join("");
      const rows = this._visible().map((d) => {
        const e = this._edits[d.id] || {};
        const name = e.name ?? d.name, area = "area_id" in e ? e.area_id : d.area_id;
        return `<tr>
        <td>${d.new ? '<span class="badge">new</span> ' : ""}${d.ignored ? '<span class="pill">ignored</span> ' : ""}<input data-n="${d.id}" value="${this._esc(name)}" size="22" style="max-width:100%"></td>
        <td data-l="Type"><span class="pill">${this._esc(d.protocol)}</span></td>
        <td class="muted" data-l="Model">${this._esc(this._val(d, "model"))}</td>
        <td data-l="Area"><select data-a="${d.id}">${opts(area)}</select></td>
        <td data-l="State" class="${d.available ? "ok" : "bad"}">${d.available ? "online" : "offline"}</td>
        <td class="muted" data-l="Info">${d.battery != null ? d.battery + "%" : ""}${d.linkquality != null ? " LQI " + d.linkquality : ""}</td>
        <td class="act" style="white-space:nowrap"><button class="btn ghost" data-s="${d.id}">Save</button>
          <button class="btn ghost" data-ig="${d.id}" data-v="${d.ignored ? 0 : 1}">${d.ignored ? "Unignore" : "Ignore"}</button>
          ${d.removable ? `<button class="btn ghost stop" data-rm="${d.id}">Remove</button>` : ""}</td></tr>`;
      }).join("");
      return rows || '<tr><td colspan="7" class="muted">No devices match the filters</td></tr>';
    }
    _r_devices() {
      const f = this._f, { key, dir } = this._sort;
      const protos = [...new Set(this._devices.map((d) => d.protocol))].sort();
      const sel = (id, cur, items) => `<select id="${id}">${items.map(([v, l]) => `<option value="${this._esc(v)}" ${v === cur ? "selected" : ""}>${this._esc(l)}</option>`).join("")}</select>`;
      const head = this._cols().map(([k, l]) =>
        `<th class="sortable" data-k="${k}">${l}<span class="arrow">${key === k ? (dir > 0 ? " \u25B2" : " \u25BC") : ""}</span></th>`).join("");
      return `<div class="card"><h2>Devices (<span id="dcount">${this._visible().length}</span> of ${this._devices.length})</h2>
        <div class="row" style="margin-bottom:8px">
          <label><input type="checkbox" id="f-new" ${f.newOnly ? "checked" : ""}> New only</label>
          <label><input type="checkbox" id="f-unused" ${f.unusedOnly ? "checked" : ""}> Offline / unused only</label>
          <label><input type="checkbox" id="f-ign" ${f.showIgnored ? "checked" : ""}> Show ignored (${this._devices.filter((d) => d.ignored).length})</label>
          <button class="btn ghost" id="f-clear">Clear filters</button>
        </div>
        <div style="overflow:auto"><table class="dev">
        <tr class="hd">${head}<th></th></tr>
        <tr class="filters">
          <td><input id="f-name" placeholder="Filter name" value="${this._esc(f.name)}" size="16"></td>
          <td>${sel("f-protocol", f.protocol, [["", "All"], ...protos.map((x) => [x, x])])}</td>
          <td><input id="f-model" placeholder="Filter model" value="${this._esc(f.model)}" size="16"></td>
          <td>${sel("f-area", f.area, [["", "All"], ["__none", "(no area)"], ...this._areas.map((a) => [a.id, a.name])])}</td>
          <td>${sel("f-state", f.state, [["", "All"], ["online", "online"], ["offline", "offline"]])}</td>
          <td></td><td></td></tr>
        <tbody id="drows">${this._rows()}</tbody></table></div></div>`;
    }
    _b_devices(m) {
      const body = m.querySelector("#drows");
      const bindRows = () => {
        body.querySelectorAll("input[data-n]").forEach((el) => (el.oninput = () => { (this._edits[el.dataset.n] ||= {}).name = el.value; }));
        body.querySelectorAll("select[data-a]").forEach((el) => (el.onchange = () => { (this._edits[el.dataset.a] ||= {}).area_id = el.value || null; }));
        body.querySelectorAll("button[data-s]").forEach((b) => (b.onclick = async () => {
          const id = b.dataset.s;
          const name = body.querySelector(`input[data-n="${id}"]`).value.trim();
          const area_id = body.querySelector(`select[data-a="${id}"]`).value || null;
          try { await this._ws("update_device", { device_id: id, name, area_id }); delete this._edits[id]; this._msg = "Saved."; } catch (e) { this._msg = "Save failed: " + e.message; }
          this._refresh();
        }));
        body.querySelectorAll("button[data-ig]").forEach((b) => (b.onclick = async () => {
          try { await this._ws("set_ignored", { device_id: b.dataset.ig, ignored: b.dataset.v === "1" }); this._msg = b.dataset.v === "1" ? "Ignored. Use 'Show ignored' to see it again." : "Restored."; } catch (e) { this._msg = e.message; }
          this._refresh();
        }));
        body.querySelectorAll("button[data-rm]").forEach((b) => (b.onclick = async () => {
          const d = this._devices.find((x) => x.id === b.dataset.rm); if (!d) return;
          const live = d.available ? "\n\nThis device is ONLINE and in use." : "";
          if (!confirm(`Remove "${d.name}" from the ${d.protocol} network and Sentinel Hub? Its entities and history link will be deleted and it must be re-paired to come back.${live}`)) return;
          let force = false;
          if (d.protocol === "zigbee" && !d.available) force = confirm("Device is offline. Force-remove (skips waiting for the device to acknowledge)? OK = force, Cancel = normal remove.");
          try { await this._ws("remove_device", { device_id: d.id, force }); this._msg = `Removal of "${d.name}" requested.`; } catch (e) { this._msg = "Remove failed: " + e.message; }
          setTimeout(() => this._refresh(), 1500);
        }));
      };
      // filters/sort update only the table body so typed text keeps focus
      const apply = () => { body.innerHTML = this._rows(); m.querySelector("#dcount").textContent = this._visible().length; bindRows(); };
      const bind = (id, key, ev = "input", get = (el) => el.value) => {
        const el = m.querySelector(id); if (el) el.addEventListener(ev, () => { this._f[key] = get(el); apply(); });
      };
      bind("#f-name", "name"); bind("#f-model", "model");
      bind("#f-protocol", "protocol", "change"); bind("#f-area", "area", "change"); bind("#f-state", "state", "change");
      bind("#f-new", "newOnly", "change", (el) => el.checked);
      bind("#f-unused", "unusedOnly", "change", (el) => el.checked);
      bind("#f-ign", "showIgnored", "change", (el) => el.checked);
      m.querySelector("#f-clear").onclick = () => { this._f = { name: "", model: "", protocol: "", area: "", state: "", newOnly: false, showIgnored: false, unusedOnly: false }; this._render(); };
      m.querySelectorAll("th.sortable").forEach((th) => (th.onclick = () => {
        const k = th.dataset.k, s = this._sort;
        this._sort = s.key === k ? (s.dir === 1 ? { key: k, dir: -1 } : { key: null, dir: 1 }) : { key: k, dir: 1 };
        this._render();
      }));
      bindRows();
    }

    /* ---------- discovered integrations ---------- */
    _r_discovered() {
      if (this._flow) return this._r_flow();
      const rows = this._flows.map((f) => `<tr><td>${this._esc(f.title)}</td><td><span class="pill">${this._esc(f.handler)}</span></td><td class="muted">${this._esc(f.source)}</td>
        <td><button class="btn" data-c="${f.flow_id}">Set up</button> <button class="btn ghost" data-i="${f.flow_id}">Ignore</button></td></tr>`).join("");
      return `<div class="card"><h2>Discovered, awaiting setup</h2><table class="rs">${rows || '<tr><td class="muted">Nothing discovered right now.</td></tr>'}</table></div>`;
    }
    _r_flow() {
      const f = this._flow;
      if (f.type === "form") {
        const fields = (f.data_schema || []).map((x) => this._field(x, f.errors)).join("");
        return `<div class="card"><h2>${this._esc(f.handler)}${f.step_id ? " - " + this._esc(f.step_id) : ""}</h2>
          ${f.errors?.base ? `<div class="err">${this._esc(f.errors.base)}</div>` : ""}
          <form id="ff">${fields || '<p class="muted">Confirm to continue.</p>'}<div class="row"><button class="btn" type="submit">Submit</button><button class="btn ghost" type="button" id="fx">Cancel</button></div></form></div>`;
      }
      if (f.type === "create_entry") return `<div class="card"><h2>Done</h2><p class="ok">${this._esc(f.title || "Set up")} added.</p><button class="btn" id="fx">Close</button></div>`;
      if (f.type === "abort") return `<div class="card"><h2>Stopped</h2><p>${this._esc(f.reason || "aborted")}</p><button class="btn" id="fx">Close</button></div>`;
      return `<div class="card"><h2>${this._esc(f.type)}</h2><p class="muted">This step needs the full Sentinel Hub interface; ask an administrator.</p><button class="btn" id="fx">Close</button></div>`;
    }
    _field(x, errors) {
      const n = this._esc(x.name), err = errors?.[x.name] ? `<span class="bad">${this._esc(errors[x.name])}</span>` : "";
      let inp;
      if (x.type === "boolean") inp = `<input type="checkbox" name="${n}" ${x.default ? "checked" : ""}>`;
      else if (x.type === "select") inp = `<select name="${n}">${(x.options || []).map((o) => { const v = Array.isArray(o) ? o[0] : o, l = Array.isArray(o) ? o[1] : o; return `<option value="${this._esc(v)}" ${v === x.default ? "selected" : ""}>${this._esc(l)}</option>`; }).join("")}</select>`;
      else if (["integer", "float"].includes(x.type)) inp = `<input type="number" step="${x.type === "float" ? "any" : "1"}" name="${n}" value="${this._esc(x.default ?? "")}" ${x.required ? "required" : ""}>`;
      else inp = `<input type="${/password|token|secret/i.test(x.name) ? "password" : "text"}" name="${n}" value="${this._esc(x.default ?? "")}" ${x.required ? "required" : ""}>`;
      return `<div class="field"><label>${n}${x.required ? " *" : ""}</label>${inp}${err}</div>`;
    }
    _b_discovered(m) {
      const step = async (flow_id, user_input) => {
        try { const r = await this._ws("flow_configure", { flow_id, user_input }); this._flow = { ...r, flow_id: r.flow_id || flow_id }; }
        catch (e) { this._msg = "Setup failed: " + e.message; this._flow = null; }
        this._refresh();
      };
      m.querySelectorAll("button[data-c]").forEach((b) => (b.onclick = () => step(b.dataset.c, null)));
      m.querySelectorAll("button[data-i]").forEach((b) => (b.onclick = async () => { try { await this._ws("flow_abort", { flow_id: b.dataset.i }); } catch (e) { this._msg = e.message; } this._refresh(); }));
      m.querySelector("#fx")?.addEventListener("click", () => { this._flow = null; this._render(); });
      const ff = m.querySelector("#ff");
      if (ff) ff.onsubmit = (e) => {
        e.preventDefault();
        const out = {};
        for (const x of this._flow.data_schema || []) {
          const el = ff.elements[x.name]; if (!el) continue;
          if (x.type === "boolean") out[x.name] = el.checked;
          else if (["integer", "float"].includes(x.type)) { if (el.value !== "") out[x.name] = Number(el.value); }
          else if (el.value !== "") out[x.name] = el.value;
        }
        step(this._flow.flow_id, out);
      };
    }
  }
  customElements.define("hub-mgmt-panel", HubInstallerPanel);
})();
