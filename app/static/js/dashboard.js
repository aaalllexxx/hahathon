// CodeGuardian AI — fully dynamic dashboard
const PAGE_SIZE = 8;
const state = {
  ui: null, stats: null, checks: [], repositories: [], logs: [], settings: null,
  aiThinking: false, activePeriod: 'week',
  selectedRepositoryIdFilter: '', selectedCheckId: null, selectedRepositoryId: null,
  activeView: 'dashboard', chart: null, repoChart: null,
  pages: { dashboard: 1, pr: 1, repo: 1, logs: 1, gate: 1 },
  projectMenuOpen: false,
  aiMessages: [{ role: 'bot', text: 'Привет! Я подключён к CodeGuardian. Спроси про проверку, CWE, политики или вставь код.' }],
};

/* ── helpers ── */
const qs = (s, r = document) => r.querySelector(s);
const qsa = (s, r = document) => [...r.querySelectorAll(s)];
const escapeHtml = v => String(v ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
function renderMd(raw) {
  let h = escapeHtml(raw);
  // code blocks ```lang\n...\n```
  h = h.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => `<pre class="code-block"><code>${code.trim()}</code></pre>`);
  // inline code
  h = h.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
  // bold
  h = h.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // italic
  h = h.replace(/(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)/g, '<em>$1</em>');
  // headers
  h = h.replace(/^### (.+)$/gm, '<h4>$1</h4>');
  h = h.replace(/^## (.+)$/gm, '<h3>$1</h3>');
  h = h.replace(/^# (.+)$/gm, '<h2>$1</h2>');
  // markdown tables
  h = h.replace(/((?:^\|.+\|$\n?)+)/gm, (block) => {
    const rows = block.trim().split('\n').filter(r => r.trim());
    if (rows.length < 2) return block;
    const parseRow = r => r.split('|').slice(1, -1).map(c => c.trim());
    const hdr = parseRow(rows[0]);
    const isSep = r => /^[\s|:-]+$/.test(r);
    const startIdx = isSep(rows[1]) ? 2 : 1;
    const thRow = startIdx === 2 ? `<tr>${hdr.map(c => `<th>${c}</th>`).join('')}</tr>` : '';
    const bodyRows = rows.slice(startIdx === 2 ? 2 : 0).map(r => `<tr>${parseRow(r).map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
    return `<div style="overflow-x:auto"><table>${thRow ? '<thead>'+thRow+'</thead>' : ''}<tbody>${bodyRows}</tbody></table></div>`;
  });
  // unordered list items
  h = h.replace(/^[\-\*] (.+)$/gm, '<li>$1</li>');
  h = h.replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>');
  // numbered list
  h = h.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  // links [text](url)
  h = h.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  // line breaks (double newline → paragraph, single → br)
  h = h.replace(/\n{2,}/g, '</p><p>');
  h = h.replace(/\n/g, '<br>');
  return `<p>${h}</p>`.replace(/<p><\/p>/g, '');
}
function deep(obj, path) { return path.split('.').reduce((o, k) => o?.[k], obj); }

const MSK = { timeZone: 'Europe/Moscow' };
function ensureUTC(v) {
  let s = String(v || '');
  if (s && !s.endsWith('Z') && !s.includes('+') && !/-\d{2}:\d{2}$/.test(s)) s += 'Z';
  return new Date(s);
}
function formatDate(v) {
  if (!v) return 'Нет данных';
  const d = ensureUTC(v), now = new Date();
  const dStr = d.toLocaleDateString('ru-RU', MSK), nowStr = now.toLocaleDateString('ru-RU', MSK);
  const y = new Date(now); y.setDate(now.getDate() - 1);
  const yStr = y.toLocaleDateString('ru-RU', MSK);
  const pfx = dStr === nowStr ? 'Сегодня' : dStr === yStr ? 'Вчера' : dStr;
  return pfx + ', ' + d.toLocaleTimeString('ru-RU', { ...MSK, hour: '2-digit', minute: '2-digit' });
}
function formatTime(v) { return v ? ensureUTC(v).toLocaleTimeString('ru-RU',{ ...MSK, hour:'2-digit',minute:'2-digit',second:'2-digit'}) : '-'; }

/* palette-driven renderers */
function sev(s) {
  const k = String(s || 'LOW').toUpperCase();
  const p = state.ui?.theme?.severity_palette?.[k];
  return `<span class="severity-pill ${k.toLowerCase()}">${p?.label || k}</span>`;
}
function stat(s) {
  const p = state.ui?.theme?.status_palette?.[s];
  return `<span class="status-pill ${s}">${p?.icon ? '<i class="'+p.icon+'"></i> ' : ''}${p?.label || s}</span>`;
}
function levelPill(lv) {
  const p = state.ui?.theme?.level_palette?.[lv];
  return `<span class="level-pill ${(lv||'').toLowerCase()}">${p?.label || lv}</span>`;
}
function levelStatus(lv) { return state.ui?.theme?.level_palette?.[lv]?.status || lv; }
function provIcon(prov) { return state.ui?.theme?.provider_icons?.[prov] || 'fa-solid fa-code-branch'; }
function originMeta(o) { return state.ui?.theme?.origin_palette?.[o] || { label: o, icon: 'fa-solid fa-bolt', color: '#8b949e' }; }
function stateDot(v, l) { return `<span class="state-dot ${v}">${escapeHtml(l)}</span>`; }
function emptyRow(c, t) { return `<tr><td colspan="${c}"><div class="empty-state">${escapeHtml(t)}</div></td></tr>`; }
function parseSummary(ch) { try { return ch.summary ? JSON.parse(ch.summary) : {}; } catch { return {}; } }

async function fetchJson(url, opts = {}) {
  const r = await fetch(url, { headers: {'Content-Type':'application/json'}, ...opts });
  if (!r.ok) { let d; try { d = (await r.json()).detail; } catch { d = await r.text(); } const e = new Error(typeof d === 'object' ? JSON.stringify(d) : (d || 'HTTP ' + r.status)); e.status = r.status; e.detail = d; throw e; }
  return r.json();
}

function showToast(text, kind = 'info') {
  const s = qs('#toastStack'); if (!s) return;
  const el = document.createElement('div'); el.className = `toast ${kind}`;
  el.innerHTML = `<i class="fa-solid ${kind==='error'?'fa-circle-xmark':kind==='success'?'fa-circle-check':'fa-circle-info'}"></i><span>${escapeHtml(text)}</span>`;
  s.appendChild(el); setTimeout(() => el.classList.add('show'), 10);
  setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 300); }, 4500);
}

/* ── data loading ── */
async function loadAll() {
  try {
    const [ui, stats, checks, repos, logs, sets] = await Promise.all([
      fetchJson('/api/ui'), fetchJson('/api/stats?period=' + (state.activePeriod || 'week')), fetchJson('/api/checks'),
      fetchJson('/api/repositories'), fetchJson('/api/logs'), fetchJson('/api/settings'),
    ]);
    state.ui = ui; state.stats = stats; state.checks = checks;
    state.repositories = repos; state.logs = logs; state.settings = sets.values;
    buildViews();
    renderAll();
  } catch (err) { console.error(err); showToast('Не удалось загрузить данные: ' + err.message, 'error'); }
}

/* ── dynamic view builder ── */
function buildViews() {
  if (!state.ui) return;
  const root = qs('#viewsRoot');
  const nav = state.ui.navigation || [];
  const existing = new Set(qsa('.view', root).map(v => v.dataset.view));
  nav.forEach(n => {
    if (existing.has(n.view)) return;
    const div = document.createElement('div');
    div.className = 'view'; div.dataset.view = n.view;
    div.id = 'view-' + n.view;
    div.innerHTML = buildViewHtml(n.view);
    root.appendChild(div);
  });
  populateFilters();
}

function buildViewHtml(view) {
  switch (view) {
    case 'dashboard': return `
      <div class="kpi-grid" id="dashboardKpi"></div>
      <div class="chart-panel panel"><div class="panel-header"><h2><i class="fa-solid fa-chart-area"></i> Тренд уязвимостей</h2></div><div class="chart-wrap"><canvas id="trendChart"></canvas></div><div class="segmented-control" id="trendSegmented"></div></div>
      <div class="main-grid"><div class="checks-panel panel"><div class="panel-header"><h2><i class="fa-solid fa-list-check"></i> Последние проверки</h2></div><div class="table-wrap"><table class="checks-table"><thead><tr><th>ID</th><th>Репозиторий</th><th>Автор</th><th>Ветка</th><th>Severity</th><th>Статус</th><th>Дата</th><th></th></tr></thead><tbody id="dashboardChecksBody"></tbody></table></div><div class="table-footer" id="dashboardPager"></div></div><div class="top-vulns panel" id="topVulns"></div></div>`;
    case 'checks': return `
      <div class="kpi-grid" id="prKpi"></div>
      <div class="page-panel panel checks-panel"><div class="panel-header"><h2><i class="fa-solid fa-code-pull-request"></i> Все проверки PR</h2><div class="filters-inline"><div class="search-field compact"><i class="fa-solid fa-magnifying-glass"></i><input id="prSearch" placeholder="Поиск…" autocomplete="off"></div><div class="filter-select"><i class="fa-solid fa-filter"></i><select id="prSeverityFilter" data-filter-key="severity"></select></div><div class="filter-select"><i class="fa-solid fa-flag"></i><select id="prStatusFilter" data-filter-key="status"></select></div></div></div><div class="table-wrap"><table class="checks-table"><thead><tr><th>ID</th><th>Репозиторий</th><th>Автор</th><th>Ветка</th><th>Коммит</th><th>Severity</th><th>Статус</th><th>Origin</th><th>Дата</th><th></th></tr></thead><tbody id="prChecksBody"></tbody></table></div><div class="table-footer" id="prPager"></div></div>`;
    case 'gate': return `
      <div class="kpi-grid" id="gateKpi"></div>
      <div class="page-panel panel checks-panel"><div class="panel-header"><h2><i class="fa-solid fa-shield-halved"></i> Заблокированные запросы</h2></div><div class="table-wrap"><table class="checks-table"><thead><tr><th>ID</th><th>Репозиторий</th><th>Автор</th><th>Ветка</th><th>Severity</th><th>Origin</th><th>Enforcement</th><th>Дата</th><th></th></tr></thead><tbody id="gateBody"></tbody></table></div><div class="table-footer" id="gatePager"></div></div>`;
    case 'repositories': return `
      <div class="kpi-grid" id="repoKpi"></div>
      <div class="section-title"><h2><i class="fa-regular fa-folder"></i> Подключённые репозитории</h2><button class="primary-button" id="connectRepoBtn"><i class="fa-solid fa-plus"></i> <span data-i18n="connect_repository"></span></button></div>
      <div id="repoCards"></div>`;
    case 'logs': return `
      <div class="kpi-grid" id="logKpi"></div>
      <div class="logs-grid"><div class="logs-panel panel"><div class="panel-header"><h2><i class="fa-regular fa-rectangle-list"></i> Журнал аудита</h2><div class="filters-inline"><div class="search-field compact"><i class="fa-solid fa-magnifying-glass"></i><input id="logSearch" placeholder="Поиск…" autocomplete="off"></div><div class="filter-select"><i class="fa-solid fa-layer-group"></i><select id="logLevelFilter" data-filter-key="log_levels"></select></div></div></div><div class="table-wrap"><table class="checks-table logs-table"><thead><tr><th>Время</th><th>Уровень</th><th>Событие</th><th>Источник</th><th>Актор</th><th>Статус</th><th>Сообщение</th></tr></thead><tbody id="logsBody"></tbody></table></div><div class="table-footer" id="logsPager"></div></div>
      <div class="detection-chain panel" id="detectionChain"></div>
      <div class="raw-log panel"><h2><i class="fa-solid fa-terminal"></i> Raw Log</h2><pre id="rawLogs"></pre></div>
      <div class="components-panel panel" id="componentsPanel"></div>
      <div class="quick-actions panel" id="quickActions"></div></div>`;
    case 'settings': return `
      <div class="settings-grid" id="settingsGrid"></div>
      <div class="panel" style="padding:16px;margin-top:16px"><h2 style="margin:0 0 12px"><i class="fa-solid fa-robot"></i> AI Tools</h2><div class="tool-list" id="aiToolsList"></div></div>`;
    default: return `<div class="placeholder-box"><i class="fa-solid fa-puzzle-piece"></i><h2>${escapeHtml(view)}</h2><p>Раздел в разработке</p></div>`;
  }
}

/* ── render all ── */
function buildKpiFromSpec(specs, statsObj) {
  if (!specs || !statsObj) return '';
  return specs.map(sp => {
    const val = sp.value !== undefined ? sp.value : deep(statsObj, sp.path);
    return `<article class="kpi-card ${sp.tone||'blue'}"><i class="${escapeHtml(sp.icon)}"></i><div><span>${escapeHtml(sp.label)}</span><strong>${escapeHtml(val ?? '—')}</strong><small>${escapeHtml(sp.hint||'')}</small></div></article>`;
  }).join('');
}

function renderKpis() {
  if (!state.stats || !state.ui) return;
  const specs = state.ui.kpi_specs || {};
  const el = id => qs('#' + id);
  if (el('dashboardKpi')) el('dashboardKpi').innerHTML = buildKpiFromSpec(specs.dashboard, state.stats);
  if (el('prKpi')) el('prKpi').innerHTML = buildKpiFromSpec(specs.checks, state.stats);
  if (el('repoKpi')) el('repoKpi').innerHTML = buildKpiFromSpec(specs.repositories, state.stats);
  if (el('logKpi')) el('logKpi').innerHTML = buildKpiFromSpec(specs.logs, state.stats);
  if (el('gateKpi')) el('gateKpi').innerHTML = buildKpiFromSpec(specs.gate, state.stats);
}

function renderAll() {
  renderShell();
  renderKpis();
  renderProjectSwitcher();
  renderTrend();
  renderTopVulnerabilities();
  renderDashboardChecks();
  renderPrChecks();
  renderGate();
  renderRepositories();
  renderLogs();
  renderSettings();
  renderNotifications();
  renderPolicyCard();
  renderAiTools();
  renderDetectionChain();
}

/* ── shell ── */
function renderShell() {
  if (!state.ui) return;
  const { app, user, navigation } = state.ui;
  qs('#brandText').innerHTML = escapeHtml(app.title.replace(/\s*AI$/i,'')) + ' <strong>AI</strong>';
  const unEl = qs('#userName'); if (unEl) unEl.textContent = user.name;
  qs('#userAvatar').textContent = user.initials;
  const navEl = qs('#navList');
  navEl.innerHTML = navigation.map(n => {
    const badge = n.badge_key && state.ui.notifications?.[n.badge_key] ? `<span class="nav-badge">${state.ui.notifications[n.badge_key]}</span>` : '';
    return `<button class="nav-item ${n.view === state.activeView ? 'active' : ''}" data-view="${escapeHtml(n.view)}"><i class="${escapeHtml(n.icon)}"></i><span>${escapeHtml(n.label)}</span>${badge}</button>`;
  }).join('');
  switchView(state.activeView);
}

/* ── project switcher ── */
function renderProjectSwitcher() {
  const el = qs('#projectSwitcher'); if (!el) return;
  const repos = state.repositories || [];
  const selId = state.selectedRepositoryIdFilter;
  const sel = repos.find(r => String(r.id) === String(selId));
  const allLabel = state.ui?.i18n?.all_repositories || 'Все репозитории';
  const name = sel ? sel.name : allLabel;
  const prov = sel ? sel.provider : 'GitLab';
  const branch = sel ? sel.branch : '';
  el.innerHTML = `
    <button class="project-trigger" id="projectTrigger">
      <div class="project-provider"><i class="${provIcon(prov)}"></i></div>
      <div class="project-trigger-text"><strong>${escapeHtml(name)}</strong><small>${escapeHtml(branch || 'все ветки')}</small></div>
      <i class="fa-solid fa-chevron-down"></i>
    </button>
    <div class="project-menu ${state.projectMenuOpen ? 'open' : ''}" id="projectMenu">
      <div class="search-field compact"><i class="fa-solid fa-magnifying-glass"></i><input id="projectSearchInput" placeholder="Поиск репозитория…" autocomplete="off"></div>
      <div class="project-list" id="projectList">
        <button class="project-option ${!selId ? 'active' : ''}" data-repo-id="">
          <div class="project-provider"><i class="fa-solid fa-layer-group"></i></div>
          <div><strong>${escapeHtml(allLabel)}</strong><small>${repos.length} репозиториев</small></div>
          <span class="policy-chip"><i class="fa-solid fa-check"></i></span>
        </button>
        ${repos.map(r => `
          <button class="project-option ${String(r.id) === String(selId) ? 'active' : ''}" data-repo-id="${r.id}">
            <div class="project-provider"><i class="${provIcon(r.provider)}"></i></div>
            <div><strong>${escapeHtml(r.name)}</strong><small>${escapeHtml(r.branch || 'main')} · ${r.checks_count || 0} проверок</small></div>
            ${r.blocked_count ? '<span class="severity-pill critical">'+r.blocked_count+' блок</span>' : '<span class="policy-chip"><i class="fa-solid fa-check"></i></span>'}
          </button>
        `).join('')}
      </div>
    </div>`;
}

/* ── trend chart ── */
function renderTrend() {
  const canvas = qs('#trendChart'); if (!canvas || !state.stats) return;
  const ctx = canvas.getContext('2d');
  if (state.chart) state.chart.destroy();
  const labels = state.stats.trend?.labels || [];
  const vals = state.stats.trend?.values || [];
  const activity = state.stats.check_activity?.values || [];
  state.chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Уязвимости', data: vals, borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,.12)', fill: true, tension: 0.35 },
        { label: 'Проверки', data: activity, borderColor: '#2f81f7', backgroundColor: 'rgba(47,129,247,.08)', fill: true, tension: 0.35 },
      ],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#8b949e' } } }, scales: { x: { ticks: { color: '#8b949e' }, grid: { color: 'rgba(39,49,63,.5)' } }, y: { beginAtZero: true, ticks: { color: '#8b949e' }, grid: { color: 'rgba(39,49,63,.5)' } } } },
  });
  const seg = qs('#trendSegmented');
  if (seg && state.ui?.segmented_periods) {
    const activePeriod = state.activePeriod || 'week';
    seg.innerHTML = state.ui.segmented_periods.map(p => `<button class="${p.value === activePeriod ? 'active' : ''}" data-period="${p.value}">${escapeHtml(p.label)}</button>`).join('');
  }
}

/* ── top vulnerabilities ── */
function renderTopVulnerabilities() {
  const el = qs('#topVulns'); if (!el || !state.stats) return;
  const items = state.stats.top_vulnerabilities || [];
  const max = Math.max(...items.map(i => i.count), 1);
  el.innerHTML = `<div class="panel-header"><h2><i class="fa-solid fa-ranking-star"></i> Топ уязвимостей</h2></div>` +
    (items.length ? items.map(i => `<div class="vuln-row"><header><span>${escapeHtml(i.name)}</span><span>${i.count}</span></header><div class="progress-track"><div class="progress-bar" style="width:${(i.count/max*100).toFixed(0)}%"></div></div></div>`).join('') : '<div class="empty-state">Нет данных</div>');
}

/* ── checks tables ── */
function renderChecksTable(checks, bodyId, pagerId, pageKey, extraCols) {
  const body = qs('#' + bodyId); if (!body) return;
  const total = checks.length;
  const page = state.pages[pageKey] || 1;
  const start = (page - 1) * PAGE_SIZE;
  const slice = checks.slice(start, start + PAGE_SIZE);
  if (!slice.length) { body.innerHTML = emptyRow(extraCols ? 10 : 8, 'Нет проверок'); }
  else {
    body.innerHTML = slice.map(ch => {
      const repo = ch.repository?.name || '—';
      const om = originMeta(ch.origin);
      return `<tr class="${ch.id === state.selectedCheckId ? 'selected' : ''}" data-check-id="${ch.id}">
        <td>#${ch.id}</td><td>${escapeHtml(repo)}</td><td>${escapeHtml(ch.author || '—')}</td><td>${escapeHtml(ch.branch || '—')}</td>
        ${extraCols ? '<td><code>'+ escapeHtml((ch.commit_sha||'').slice(0,8)) +'</code></td>' : ''}
        <td>${sev(ch.severity)}</td><td>${stat(ch.status)}</td>
        ${extraCols ? '<td><span style="color:'+om.color+'"><i class="'+om.icon+'"></i> '+escapeHtml(om.label)+'</span></td>' : ''}
        <td>${formatDate(ch.created_at)}</td>
        <td><button class="detail-button" data-check-id="${ch.id}"><i class="fa-solid fa-arrow-right"></i></button></td>
      </tr>`;
    }).join('');
  }
  renderPager(pagerId, pageKey, total);
}

function renderDashboardChecks() {
  const filtered = filterChecks(state.checks);
  renderChecksTable(filtered, 'dashboardChecksBody', 'dashboardPager', 'dashboard', false);
}

function renderPrChecks() {
  const filtered = filterChecks(state.checks);
  renderChecksTable(filtered, 'prChecksBody', 'prPager', 'pr', true);
}

function renderGate() {
  const blocked = state.checks.filter(c => c.status === 'blocked');
  const body = qs('#gateBody'); if (!body) return;
  const page = state.pages.gate || 1;
  const start = (page - 1) * PAGE_SIZE;
  const slice = blocked.slice(start, start + PAGE_SIZE);
  if (!slice.length) { body.innerHTML = emptyRow(9, 'Нет заблокированных запросов'); }
  else {
    body.innerHTML = slice.map(ch => {
      const om = originMeta(ch.origin);
      return `<tr data-check-id="${ch.id}">
        <td>#${ch.id}</td><td>${escapeHtml(ch.repository?.name||'—')}</td><td>${escapeHtml(ch.author||'—')}</td><td>${escapeHtml(ch.branch||'—')}</td>
        <td>${sev(ch.severity)}</td>
        <td><span style="color:${om.color}"><i class="${om.icon}"></i> ${escapeHtml(om.label)}</span></td>
        <td>${escapeHtml(ch.enforcement||'—')}</td>
        <td>${formatDate(ch.created_at)}</td>
        <td><button class="detail-button" data-check-id="${ch.id}"><i class="fa-solid fa-arrow-right"></i></button></td>
      </tr>`;
    }).join('');
  }
  renderPager('gatePager', 'gate', blocked.length);
}

function filterChecks(checks) {
  let list = [...checks];
  if (state.selectedRepositoryIdFilter) list = list.filter(c => String(c.repository_id) === String(state.selectedRepositoryIdFilter));
  const sevF = qs('#prSeverityFilter')?.value; if (sevF && sevF !== 'all') list = list.filter(c => c.severity.toLowerCase() === sevF);
  const stF = qs('#prStatusFilter')?.value; if (stF && stF !== 'all') list = list.filter(c => c.status === stF);
  const q = (qs('#prSearch')?.value || '').trim().toLowerCase();
  if (q) list = list.filter(c => (c.repository?.name||'').toLowerCase().includes(q) || (c.author||'').toLowerCase().includes(q) || (c.branch||'').toLowerCase().includes(q));
  return list;
}

function renderPager(containerId, pageKey, total) {
  const el = qs('#' + containerId); if (!el) return;
  const pages = Math.ceil(total / PAGE_SIZE) || 1;
  const cur = state.pages[pageKey] || 1;
  const i18n = state.ui?.i18n || {};
  const shown = Math.min(total, cur * PAGE_SIZE);
  el.innerHTML = `<span>${(i18n.shown_of || 'Показано {shown} из {total}').replace('{shown}', shown).replace('{total}', total)}</span>
    <div class="pager">${Array.from({length: pages}, (_, i) => `<button class="${i+1===cur?'active':''}" data-page="${i+1}" data-page-key="${pageKey}">${i+1}</button>`).join('')}</div>`;
}

/* ── repositories ── */
function renderRepositories() {
  const el = qs('#repoCards'); if (!el) return;
  const repos = state.repositories || [];
  if (!repos.length) { el.innerHTML = '<div class="empty-state">Нет подключённых репозиториев</div>'; return; }
  el.innerHTML = repos.map(r => {
    const ss = r.severity_summary || {};
    return `<div class="panel repositories-panel" style="margin-bottom:16px" data-repo-detail="${r.id}">
      <div class="panel-header"><div class="repo-title-cell"><div class="repo-icon"><i class="${provIcon(r.provider)}"></i></div><div class="repo-name"><strong>${escapeHtml(r.name)}</strong><small>${escapeHtml(r.branch || 'main')}</small></div></div>
      <div style="display:flex;gap:12px;align-items:center">${stateDot(r.status, r.status === 'active' ? 'Активен' : 'Ошибка')} ${stateDot(r.webhook, r.webhook === 'online' ? 'Webhook online' : 'Не настроен')} <button class="icon-button" data-delete-repo="${r.id}" title="Удалить репозиторий" style="color:var(--red);margin-left:4px"><i class="fa-solid fa-trash"></i></button></div></div>
      <div class="repo-summary-grid">
        <div class="repo-summary-card"><strong>${r.checks_count||0}</strong><span>Проверок</span></div>
        <div class="repo-summary-card"><strong style="color:var(--red)">${ss.high||0}</strong><span>High+Crit</span></div>
        <div class="repo-summary-card"><strong style="color:var(--amber)">${ss.medium||0}</strong><span>Medium</span></div>
        <div class="repo-summary-card"><strong style="color:var(--green)">${ss.low||0}</strong><span>Low</span></div>
      </div>
      ${r.recent_checks?.length ? '<div class="mini-list">' + r.recent_checks.map(c => `<div class="mini-item"><div><strong>PR #${c.pr_number||c.id}</strong> · ${escapeHtml(c.branch||'—')} · ${formatDate(c.created_at)}</div>${sev(c.severity)} ${stat(c.status)}</div>`).join('') + '</div>' : ''}
    </div>`;
  }).join('');
  // i18n for connect button
  const btn = qs('#connectRepoBtn span[data-i18n]');
  if (btn) btn.textContent = state.ui?.i18n?.connect_repository || 'Подключить';
}

/* ── logs ── */
function renderLogs() {
  const body = qs('#logsBody'); if (!body) return;
  let list = [...(state.logs || [])];
  const lvl = qs('#logLevelFilter')?.value; if (lvl && lvl !== 'all') list = list.filter(l => l.level.toLowerCase() === lvl);
  const q = (qs('#logSearch')?.value || '').trim().toLowerCase();
  if (q) list = list.filter(l => (l.event||'').toLowerCase().includes(q) || (l.message||'').toLowerCase().includes(q) || (l.source||'').toLowerCase().includes(q) || (l.actor||'').toLowerCase().includes(q));
  const page = state.pages.logs || 1;
  const start = (page - 1) * PAGE_SIZE;
  const slice = list.slice(start, start + PAGE_SIZE);
  body.innerHTML = slice.length ? slice.map(l => `<tr>
    <td>${formatTime(l.created_at)}</td><td>${levelPill(l.level)}</td><td>${escapeHtml(l.event)}</td>
    <td>${escapeHtml(l.source||'—')}</td><td>${escapeHtml(l.actor||'—')}</td><td>${levelStatus(l.level)}</td>
    <td style="white-space:normal;max-width:340px">${escapeHtml(l.message)}</td>
  </tr>`).join('') : emptyRow(7, 'Нет логов');
  renderPager('logsPager', 'logs', list.length);
  // raw logs
  const raw = qs('#rawLogs');
  if (raw) raw.textContent = list.slice(0, 30).map(l => `[${formatTime(l.created_at)}] ${l.level} ${l.event} — ${l.message}`).join('\n');
  // components
  renderComponents();
  renderQuickActions();
}

function renderComponents() {
  const el = qs('#componentsPanel'); if (!el) return;
  const comps = [
    { name: 'Static Scanner', status: 'online' },
    { name: 'LLM Reviewer', status: state.settings?.SECURITY_USE_LLM ? 'online' : 'disabled' },
    { name: 'CVE Checker', status: state.settings?.CVE_ENABLE ? 'online' : 'disabled' },
    { name: 'Policy Engine', status: 'online' },
    { name: 'GitLab Integration', status: 'online' },
  ];
  el.innerHTML = `<h2><i class="fa-solid fa-cubes"></i> Компоненты</h2>` +
    comps.map(c => `<div class="component-row"><span>${escapeHtml(c.name)}</span><div class="progress-track" style="height:4px"><div class="progress-bar" style="width:100%;background:${c.status==='online'?'var(--green)':'var(--amber)'}"></div></div>${stateDot(c.status === 'online' ? 'online' : 'token', c.status)}</div>`).join('');
}

function renderQuickActions() {
  const el = qs('#quickActions'); if (!el || !state.ui?.quick_actions) return;
  el.innerHTML = `<h2><i class="fa-solid fa-bolt"></i> Быстрые действия</h2>` +
    state.ui.quick_actions.map(a => `<button class="outline-button" data-action="${a.key}"><i class="${a.icon}"></i> ${escapeHtml(a.label)}</button>`).join('');
}

/* ── detection chain ── */
function renderDetectionChain() {
  const el = qs('#detectionChain'); if (!el || !state.ui?.detection_chain) return;
  const chain = state.ui.detection_chain;
  el.innerHTML = `<h2><i class="fa-solid fa-diagram-project"></i> Цепочка обнаружения</h2>
    <div class="chain">${chain.map(s => `<div class="chain-step"><div class="chain-icon"><i class="fa-solid fa-check"></i></div><span>${escapeHtml(s.label)}</span></div>`).join('')}</div>`;
}

/* ── settings ── */
function renderSettings() {
  const grid = qs('#settingsGrid'); if (!grid || !state.ui?.settings_schema) return;
  const vals = state.settings || {};
  grid.innerHTML = state.ui.settings_schema.map(section => `
    <div class="panel settings-panel">
      <h2><i class="${section.icon}"></i> ${escapeHtml(section.section)}</h2>
      ${section.fields.map(f => {
        if (f.type === 'checkbox') return `<label class="toggle-row"><span>${escapeHtml(f.label)}</span><input type="checkbox" name="${f.name}" ${vals[f.name] ? 'checked' : ''}></label>`;
        return `<label>${escapeHtml(f.label)}<input type="${f.type}" name="${f.name}" value="${escapeHtml(vals[f.name] ?? '')}" placeholder="${escapeHtml(f.placeholder||'')}" ${f.min!=null?'min="'+f.min+'"':''} ${f.max!=null?'max="'+f.max+'"':''} ${f.step?'step="'+f.step+'"':''}></label>`;
      }).join('')}
    </div>
  `).join('') + `<div style="grid-column:1/-1;display:flex;gap:10px;margin-top:8px"><button class="primary-button" id="saveSettingsBtn"><i class="fa-solid fa-floppy-disk"></i> Сохранить</button><button class="outline-button" id="refreshSettingsBtn"><i class="fa-solid fa-arrows-rotate"></i> Обновить</button></div>`;
}

function renderAiTools() {
  const el = qs('#aiToolsList'); if (!el || !state.ui?.ai_tools) return;
  el.innerHTML = state.ui.ai_tools.map(t => `<span>${escapeHtml(t)}</span>`).join('');
}

/* ── notifications & policy ── */
function renderNotifications() {
  const badge = qs('#notificationBadge');
  if (badge && state.ui?.notifications) {
    const n = state.ui.notifications.attention || 0;
    badge.textContent = n; badge.style.display = n ? '' : 'none';
  }
}

function renderPolicyCard() {
  const el = qs('#policySummary'); if (!el || !state.ui?.policy) return;
  const p = state.ui.policy;
  el.innerHTML = `<div style="padding:8px 0;font-size:12px;color:var(--muted)">
    <div style="margin-bottom:6px;font-weight:700;color:var(--text)"><i class="fa-solid fa-shield-halved"></i> Политика</div>
    ${p.merge_request_blocking ? '<div class="policy-chip" style="margin:3px 0"><i class="fa-solid fa-code-pull-request"></i> Block Merge Request</div>' : ''}
    ${p.webhook_inline_comments ? '<div class="policy-chip" style="margin:3px 0"><i class="fa-regular fa-comment-dots"></i> Inline comments</div>' : ''}
    ${!p.pre_push_blocking ? '<div class="policy-chip" style="margin:3px 0;border-color:rgba(63,188,231,.34);color:#9bdfff;background:rgba(63,188,231,.12)"><i class="fa-solid fa-code-branch"></i> Push allowed</div>' : ''}
    ${p.block_on_critical ? '<div class="policy-chip" style="margin:3px 0"><i class="fa-solid fa-lock"></i> Block Critical</div>' : ''}
    ${p.block_on_high ? '<div class="policy-chip" style="margin:3px 0"><i class="fa-solid fa-lock"></i> Block High</div>' : ''}
    ${p.llm_required ? '<div class="policy-chip" style="margin:3px 0"><i class="fa-solid fa-brain"></i> LLM Required</div>' : ''}
    ${p.fail_closed ? '<div class="policy-chip" style="margin:3px 0;border-color:rgba(248,81,73,.34);color:#ff8d87;background:rgba(248,81,73,.12)"><i class="fa-solid fa-triangle-exclamation"></i> Fail Closed</div>' : ''}
  </div>`;
}

function renderAssistantCard() {
  const el = qs('#assistantCard'); if (!el) return;
  el.innerHTML = `<div class="bot-avatar"><i class="fa-solid fa-robot"></i></div><div><strong>AI Ассистент</strong><span>Online</span></div>`;
}

/* ── AI chat in drawer ── */
function openAiChatDrawer() {
  const drawer = qs('#detailDrawer');
  const shell = qs('#appShell');
  shell.classList.remove('no-drawer');
  drawer.hidden = false; drawer.classList.add('open');
  const content = qs('#drawerContent');
  state.selectedCheckId = null;
  content.innerHTML = `
    <div class="drawer-resize-handle" id="drawerResizeHandle"></div>
    <div class="drawer-header"><h2><i class="fa-solid fa-robot"></i> AI Ассистент</h2><button class="icon-button" id="closeDrawer"><i class="fa-solid fa-xmark"></i></button></div>
    <div class="ai-drawer-messages" id="aiDrawerMessages"></div>
    <form class="reply-form" id="aiDrawerForm"><input placeholder="Спросите что угодно…" autocomplete="off" required><button type="submit"><i class="fa-solid fa-paper-plane"></i></button></form>`;
  renderAiDrawerMessages();
  initDrawerResize();
}

function initDrawerResize() {
  const handle = qs('#drawerResizeHandle');
  const drawer = qs('#detailDrawer');
  if (!handle || !drawer) return;
  let startX, startW;
  function onMove(e) {
    const dx = startX - (e.clientX || e.touches?.[0]?.clientX || startX);
    drawer.style.width = Math.max(320, Math.min(window.innerWidth * 0.7, startW + dx)) + 'px';
  }
  function onUp() {
    handle.classList.remove('active');
    document.removeEventListener('mousemove', onMove);
    document.removeEventListener('mouseup', onUp);
    document.removeEventListener('touchmove', onMove);
    document.removeEventListener('touchend', onUp);
  }
  handle.addEventListener('mousedown', e => {
    e.preventDefault();
    startX = e.clientX; startW = drawer.offsetWidth;
    handle.classList.add('active');
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  });
  handle.addEventListener('touchstart', e => {
    startX = e.touches[0].clientX; startW = drawer.offsetWidth;
    handle.classList.add('active');
    document.addEventListener('touchmove', onMove, { passive: false });
    document.addEventListener('touchend', onUp);
  }, { passive: false });
}

function renderAiDrawerMessages() {
  const el = qs('#aiDrawerMessages'); if (!el) return;
  el.innerHTML = state.aiMessages.map(m => {
    const isBot = m.role === 'bot';
    const icon = isBot ? '<div class="chat-avatar bot"><i class="fa-solid fa-robot"></i></div>' : '<div class="chat-avatar user"><i class="fa-solid fa-user"></i></div>';
    return `<div class="chat-bubble ${m.role}">${icon}<div class="chat-text">${isBot ? '<small>CodeGuardian AI</small>' : '<small>Вы</small>'}<div>${isBot ? renderMd(m.text) : escapeHtml(m.text)}</div></div></div>`;
  }).join('') + (state.aiThinking ? '<div class="chat-bubble bot"><div class="chat-avatar bot"><i class="fa-solid fa-robot"></i></div><div class="chat-text"><small>CodeGuardian AI</small><div class="typing-indicator"><span></span><span></span><span></span></div></div></div>' : '');
  el.scrollTop = el.scrollHeight;
}

/* ── detail drawer ── */
function openDrawer(checkId) {
  const ch = state.checks.find(c => c.id === checkId); if (!ch) return;
  state.selectedCheckId = checkId;
  const drawer = qs('#detailDrawer');
  const shell = qs('#appShell');
  shell.classList.remove('no-drawer');
  drawer.hidden = false; drawer.classList.add('open');
  const content = qs('#drawerContent');
  const findings = ch.findings || [];
  const messages = ch.messages || [];
  const om = originMeta(ch.origin);
  content.innerHTML = `
    <div class="drawer-resize-handle" id="drawerResizeHandle"></div>
    <div class="drawer-header"><h2>Проверка #${ch.id}</h2><button class="icon-button" id="closeDrawer"><i class="fa-solid fa-xmark"></i></button></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">${sev(ch.severity)} ${stat(ch.status)} <span style="color:${om.color}"><i class="${om.icon}"></i> ${escapeHtml(om.label)}</span></div>
    <div style="font-size:13px;color:var(--muted);margin-bottom:14px">
      <div><strong>Репозиторий:</strong> ${escapeHtml(ch.repository?.name||'—')}</div>
      <div><strong>Автор:</strong> ${escapeHtml(ch.author||'—')}</div>
      <div><strong>Ветка:</strong> ${escapeHtml(ch.branch||'—')}</div>
      <div><strong>Коммит:</strong> <code>${escapeHtml((ch.commit_sha||'').slice(0,10))}</code></div>
      <div><strong>Дата:</strong> ${formatDate(ch.created_at)}</div>
      ${ch.enforcement ? '<div><strong>Enforcement:</strong> '+escapeHtml(ch.enforcement)+'</div>' : ''}
    </div>
    <div class="tabs"><button class="active" data-tab="findings">Уязвимости (${findings.length})</button><button data-tab="chat">Чат</button></div>
    <div id="drawerTabContent"></div>
    <div class="drawer-actions">
      ${ch.repository?.url ? '<a class="outline-button" href="'+escapeHtml(ch.repository.url)+'" target="_blank"><i class="fa-brands fa-gitlab"></i> Открыть</a>' : ''}
    </div>`;
  renderDrawerTab('findings', ch);
  initDrawerResize();
}

function renderDrawerTab(tab, ch) {
  const el = qs('#drawerTabContent'); if (!el) return;
  if (tab === 'findings') {
    const findings = ch.findings || [];
    if (!findings.length) { el.innerHTML = '<div class="empty-state">Нет находок</div>'; return; }
    el.innerHTML = findings.map(f => `
      <div style="margin-bottom:16px">
        <div class="finding-meta">${sev(f.severity)} <strong>${escapeHtml(f.cwe)} — ${escapeHtml(f.title)}</strong></div>
        ${f.file ? `<div class="file-card"><div><i class="fa-regular fa-file-code"></i> ${escapeHtml(f.file)}${f.line ? ':'+f.line : ''}</div></div>` : ''}
        ${f.code ? `<pre class="code-block">${escapeHtml(f.code).split('\n').map((ln,i) => '<span class="code-line'+(f.line && String(f.line) === String(i+1) ? ' problem' : '')+'">'+ln+'</span>').join('\n')}</pre>` : ''}
        ${f.reason ? `<div class="bot-note"><div class="bot-avatar"><i class="fa-solid fa-robot"></i></div><p><strong>Почему опасно:</strong> ${escapeHtml(f.reason)}</p></div>` : ''}
        ${f.fix ? `<div class="bot-note" style="border-color:rgba(63,185,80,.36);background:rgba(63,185,80,.1)"><div class="bot-avatar" style="background:linear-gradient(135deg,rgba(63,185,80,.34),rgba(47,129,247,.16))"><i class="fa-solid fa-wrench"></i></div><p><strong>Как исправить:</strong> ${escapeHtml(f.fix)}</p></div>` : ''}
        ${f.fixed_example ? `<div class="fix-card"><h3><i class="fa-solid fa-code"></i> Исправленный код</h3><pre>${escapeHtml(f.fixed_example)}</pre></div>` : ''}
        ${f.llm_verdict ? `<div style="margin-top:8px;font-size:12px;color:var(--muted)">LLM: ${escapeHtml(f.llm_verdict)} (${(f.llm_confidence*100||0).toFixed(0)}%)</div>` : ''}
      </div>
    `).join('')
  } else {
    const msgs = ch.messages || [];
    el.innerHTML = `<div class="dialogue">${msgs.map(m => `<div class="message ${m.role}"><small>${m.role === 'bot' ? 'CodeGuardian AI' : 'Вы'} · ${formatTime(m.created_at)}</small>${escapeHtml(m.text)}</div>`).join('')}</div>
      <form class="reply-form" data-check-id="${ch.id}"><input placeholder="Написать комментарий…" autocomplete="off" required><button type="submit"><i class="fa-solid fa-paper-plane"></i></button></form>`;
  }
}

function closeDrawer() {
  const drawer = qs('#detailDrawer');
  drawer.hidden = true; drawer.classList.remove('open');
  qs('#appShell').classList.add('no-drawer');
  state.selectedCheckId = null;
  renderDashboardChecks(); renderPrChecks();
}

/* ── view switching ── */
function switchView(view) {
  state.activeView = view;
  qsa('.view').forEach(v => v.classList.toggle('active', v.dataset.view === view));
  qsa('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  const titles = {}; (state.ui?.navigation || []).forEach(n => titles[n.view] = n.label);
  const h1 = qs('#pageTitle'); if (h1) h1.textContent = titles[view] || 'CodeGuardian AI';
  qs('#breadcrumbs').innerHTML = `<span class="eyebrow">${escapeHtml(state.ui?.app?.title || 'CodeGuardian AI')}</span>`;
}

/* ── AI chat modal ── */
function renderAiChat() {
  const el = qs('#aiChatMessages'); if (!el) return;
  el.innerHTML = state.aiMessages.map(m => `<div class="message ${m.role}">${m.role === 'bot' ? '<small>CodeGuardian AI</small>' : '<small>Вы</small>'}${m.role === 'bot' ? renderMd(m.text) : escapeHtml(m.text)}</div>`).join('');
  el.scrollTop = el.scrollHeight;
}

/* ── command palette ── */
function openCmdK() { const o = qs('#cmdkOverlay'); o.hidden = false; o.style.display = ''; qs('#cmdkInput').value = ''; qs('#cmdkInput').focus(); renderCmdkResults(''); }
function closeCmdK() { const o = qs('#cmdkOverlay'); o.hidden = true; o.style.display = 'none'; }
function renderCmdkResults(q) {
  const el = qs('#cmdkResults'); if (!el) return;
  const items = [];
  const lq = q.toLowerCase();
  state.checks.forEach(c => { if (!lq || (c.repository?.name||'').toLowerCase().includes(lq) || (c.author||'').toLowerCase().includes(lq) || (c.branch||'').toLowerCase().includes(lq) || String(c.id).includes(lq)) items.push({ type: 'check', id: c.id, label: `#${c.id} ${c.repository?.name||'—'} · ${c.branch||''}`, sub: c.author }); });
  state.repositories.forEach(r => { if (!lq || r.name.toLowerCase().includes(lq)) items.push({ type: 'repo', id: r.id, label: r.name, sub: r.provider }); });
  el.innerHTML = items.slice(0, 12).map(i => `<button class="project-option" data-cmdk-type="${i.type}" data-cmdk-id="${i.id}"><div class="project-provider"><i class="fa-solid ${i.type==='check'?'fa-shield':'fa-folder'}"></i></div><div><strong>${escapeHtml(i.label)}</strong><small>${escapeHtml(i.sub||'')}</small></div></button>`).join('') || '<div class="empty-state">Ничего не найдено</div>';
}

/* ── save settings ── */
async function saveSettings() {
  const grid = qs('#settingsGrid'); if (!grid) return;
  const payload = {};
  qsa('input[name]', grid).forEach(inp => {
    if (inp.type === 'checkbox') payload[inp.name] = inp.checked;
    else if (inp.type === 'number') payload[inp.name] = inp.value ? Number(inp.value) : '';
    else payload[inp.name] = inp.value;
  });
  try {
    const res = await fetchJson('/api/settings', { method: 'POST', body: JSON.stringify(payload) });
    state.settings = res.values;
    showToast('Настройки сохранены', 'success');
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

/* ── actions ── */
async function overrideCheck(id) {
  const reason = prompt('Причина снятия блокировки:');
  if (reason === null) return;
  try {
    await fetchJson(`/api/checks/${id}/override`, { method: 'POST', body: JSON.stringify({ reason, actor: state.ui?.user?.name }) });
    showToast('Блокировка снята', 'success'); await loadAll();
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

async function rerunCheck(id) {
  try {
    await fetchJson(`/api/checks/${id}/rerun`, { method: 'POST' });
    showToast('Перепроверка запущена', 'success'); await loadAll();
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

async function submitComment(checkId, text) {
  try {
    const res = await fetchJson(`/api/checks/${checkId}/comment`, { method: 'POST', body: JSON.stringify({ text }) });
    const ch = state.checks.find(c => c.id === checkId);
    if (ch) { ch.messages = res.messages; ch.findings = res.findings; }
    openDrawer(checkId);
    showToast('Комментарий добавлен', 'success');
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

async function sendAiChat(msg) {
  state.aiMessages.push({ role: 'user', text: msg });
  state.aiThinking = true;
  renderAiDrawerMessages(); renderAiChat();

  // Try SSE streaming first, fallback to regular POST
  try {
    const resp = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, check_id: state.selectedCheckId }),
    });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);

    state.aiThinking = false;
    const botMsg = { role: 'bot', text: '' };
    state.aiMessages.push(botMsg);
    renderAiDrawerMessages(); renderAiChat();

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const parts = buf.split('\n\n');
      buf = parts.pop() || '';
      for (const part of parts) {
        const lines = part.split('\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6));
        const text = lines.join('\n');
        if (text === '[DONE]') continue;
        if (text.startsWith('[ERR]')) { botMsg.text += '\n⚠️ ' + text.slice(5); }
        else { botMsg.text += text; }
        renderAiDrawerMessages(); renderAiChat();
      }
    }
    if (!botMsg.text.trim()) botMsg.text = 'Модель вернула пустой ответ.';
    renderAiDrawerMessages(); renderAiChat();
  } catch (e) {
    state.aiThinking = false;
    // Fallback to non-streaming
    try {
      const res = await fetchJson('/api/chat', { method: 'POST', body: JSON.stringify({ message: msg, check_id: state.selectedCheckId }) });
      state.aiMessages.push({ role: 'bot', text: res.answer });
    } catch (e2) {
      state.aiMessages.push({ role: 'bot', text: 'Ошибка: ' + e2.message });
    }
    renderAiDrawerMessages(); renderAiChat();
  }
}

async function connectRepo(data) {
  try {
    await fetchJson('/api/repositories', { method: 'POST', body: JSON.stringify(data) });
    showToast('Репозиторий подключён', 'success');
    qs('#connectRepoModal').classList.remove('open');
    await loadAll();
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

async function deleteRepo(id) {
  if (!confirm('Удалить репозиторий? Все связанные проверки будут удалены.')) return;
  try {
    await fetchJson(`/api/repositories/${id}`, { method: 'DELETE' });
    showToast('Репозиторий удалён', 'success');
    await loadAll();
  } catch (e) { showToast('Ошибка: ' + e.message, 'error'); }
}

async function sendInlineAiChat(msg, checkId) {
  const msgsEl = qs('#inlineAiMessages'); if (!msgsEl) return;
  msgsEl.innerHTML += `<div class="chat-bubble user"><div class="chat-text"><small>Вы</small><div>${escapeHtml(msg)}</div></div></div>`;
  msgsEl.innerHTML += `<div class="chat-bubble bot" id="inlineTyping"><div class="chat-avatar bot"><i class="fa-solid fa-robot"></i></div><div class="chat-text"><small>CodeGuardian AI</small><div class="typing-indicator"><span></span><span></span><span></span></div></div></div>`;
  msgsEl.scrollTop = msgsEl.scrollHeight;
  try {
    const resp = await fetch('/api/chat/stream', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: msg, check_id: checkId }),
    });
    const reader = resp.body.getReader(); const dec = new TextDecoder(); let buf = '', answer = '';
    const typingEl = qs('#inlineTyping');
    while (true) {
      const { done, value } = await reader.read(); if (done) break;
      buf += dec.decode(value, { stream: true });
      const parts = buf.split('\n\n'); buf = parts.pop() || '';
      for (const part of parts) {
        const lines = part.split('\n').filter(l => l.startsWith('data: ')).map(l => l.slice(6));
        const text = lines.join('\n');
        if (text === '[DONE]') continue;
        if (text.startsWith('[ERR]')) { answer += '\n⚠️ ' + text.slice(5); }
        else { answer += text; }
        if (typingEl) typingEl.querySelector('.chat-text div:last-child').innerHTML = renderMd(answer);
      }
    }
    if (typingEl) { typingEl.removeAttribute('id'); }
  } catch (e) {
    const typingEl = qs('#inlineTyping');
    if (typingEl) { typingEl.querySelector('.chat-text div:last-child').innerHTML = 'Ошибка: ' + escapeHtml(e.message); typingEl.removeAttribute('id'); }
  }
  msgsEl.scrollTop = msgsEl.scrollHeight;
}

function populateFilters() {
  if (!state.ui) return;
  qsa('select[data-filter-key]').forEach(sel => {
    const items = state.ui.filters?.[sel.dataset.filterKey] || [];
    const prev = sel.value;
    sel.innerHTML = items.map(i => `<option value="${escapeHtml(i.value)}">${escapeHtml(i.label)}</option>`).join('');
    if (prev && items.some(i => i.value === prev)) sel.value = prev;
  });
}

/* ── event listeners ── */
document.addEventListener('DOMContentLoaded', () => {
  loadAll();
  renderAssistantCard();

  // nav
  document.addEventListener('click', e => {
    const nav = e.target.closest('[data-view]');
    if (nav && nav.classList.contains('nav-item')) { switchView(nav.dataset.view); return; }

    // check detail
    const detBtn = e.target.closest('[data-check-id]');
    if (detBtn && (detBtn.tagName === 'BUTTON' || detBtn.tagName === 'TR')) { openDrawer(Number(detBtn.dataset.checkId)); return; }

    // close drawer
    if (e.target.closest('#closeDrawer')) { closeDrawer(); return; }

    // pager
    const pgBtn = e.target.closest('[data-page]');
    if (pgBtn) { state.pages[pgBtn.dataset.pageKey] = Number(pgBtn.dataset.page); renderAll(); return; }

    // project switcher
    if (e.target.closest('#projectTrigger')) { state.projectMenuOpen = !state.projectMenuOpen; renderProjectSwitcher(); return; }
    const projOpt = e.target.closest('.project-option[data-repo-id]');
    if (projOpt && qs('#projectMenu')?.contains(projOpt)) {
      state.selectedRepositoryIdFilter = projOpt.dataset.repoId;
      state.projectMenuOpen = false;
      renderProjectSwitcher(); renderDashboardChecks(); renderPrChecks();
      return;
    }

    // tabs in drawer
    const tab = e.target.closest('[data-tab]');
    if (tab && qs('#detailDrawer')?.contains(tab)) {
      qsa('.tabs button', qs('#detailDrawer')).forEach(b => b.classList.toggle('active', b === tab));
      const ch = state.checks.find(c => c.id === state.selectedCheckId);
      if (ch) renderDrawerTab(tab.dataset.tab, ch);
      return;
    }

    // override / rerun
    const ov = e.target.closest('[data-override]'); if (ov) { overrideCheck(Number(ov.dataset.override)); return; }
    const rr = e.target.closest('[data-rerun]'); if (rr) { rerunCheck(Number(rr.dataset.rerun)); return; }
    const dr = e.target.closest('[data-delete-repo]'); if (dr) { deleteRepo(Number(dr.dataset.deleteRepo)); return; }

    // modals
    if (e.target.closest('[data-close-modal]')) { e.target.closest('.modal').classList.remove('open'); return; }
    if (e.target.closest('#connectRepoBtn')) { qs('#connectRepoModal').classList.add('open'); return; }
    if (e.target.closest('[data-open-ai-chat]')) { openAiChatDrawer(); return; }

    // period switcher
    const periodBtn = e.target.closest('[data-period]');
    if (periodBtn) { state.activePeriod = periodBtn.dataset.period; loadAll(); return; }

    // save settings
    if (e.target.closest('#saveSettingsBtn')) { saveSettings(); return; }
    if (e.target.closest('#refreshSettingsBtn') || e.target.closest('#refreshButton')) { loadAll(); return; }

    // close project menu on outside click
    if (state.projectMenuOpen && !e.target.closest('#projectSwitcher')) { state.projectMenuOpen = false; renderProjectSwitcher(); }

    // cmdk
    if (e.target.closest('#cmdkTrigger')) { openCmdK(); return; }
    const cmdkItem = e.target.closest('[data-cmdk-type]');
    if (cmdkItem) {
      closeCmdK();
      if (cmdkItem.dataset.cmdkType === 'check') { switchView('checks'); openDrawer(Number(cmdkItem.dataset.cmdkId)); }
      else { switchView('repositories'); }
      return;
    }

    // quick actions
    const qa = e.target.closest('[data-action]');
    if (qa) {
      if (qa.dataset.action === 'export_logs') {
        const csv = state.logs.map(l => [l.created_at, l.level, l.event, l.source, l.actor, l.message].join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'codeguardian_logs.csv'; a.click();
        showToast('Логи экспортированы', 'success');
      }
    }
  });

  // forms
  qs('#connectRepoForm')?.addEventListener('submit', e => {
    e.preventDefault();
    const fd = new FormData(e.target);
    connectRepo({ name: fd.get('name'), url: fd.get('url'), gitlab_project_id: fd.get('gitlab_project_id') || null });
  });

  qs('#aiChatForm')?.addEventListener('submit', e => {
    e.preventDefault();
    const inp = qs('#aiChatInput'); const msg = inp.value.trim(); if (!msg) return;
    inp.value = ''; sendAiChat(msg);
  });

  document.addEventListener('submit', e => {
    const inlineForm = e.target.closest('#inlineAiForm');
    if (inlineForm) { e.preventDefault(); const inp = inlineForm.querySelector('input'); const msg = inp.value.trim(); if (!msg) return; inp.value = ''; sendInlineAiChat(msg, Number(inlineForm.dataset.checkId)); return; }
    const form = e.target.closest('.reply-form[data-check-id]');
    if (form && !form.id) { e.preventDefault(); const inp = form.querySelector('input'); submitComment(Number(form.dataset.checkId), inp.value); inp.value = ''; return; }
    const aiForm = e.target.closest('#aiDrawerForm');
    if (aiForm) { e.preventDefault(); const inp = aiForm.querySelector('input'); const msg = inp.value.trim(); if (!msg) return; inp.value = ''; sendAiChat(msg); }
  });

  // filters
  document.addEventListener('input', e => {
    if (e.target.id === 'prSearch' || e.target.id === 'logSearch' || e.target.id === 'projectSearchInput') {
      if (e.target.id === 'projectSearchInput') {
        const q = e.target.value.toLowerCase();
        qsa('.project-option[data-repo-id]').forEach(opt => { opt.style.display = (opt.textContent.toLowerCase().includes(q) || !q) ? '' : 'none'; });
      } else if (e.target.id === 'logSearch') { renderLogs(); }
      else { renderPrChecks(); renderDashboardChecks(); }
    }
  });

  document.addEventListener('change', e => {
    if (e.target.matches('[data-filter-key]')) { renderPrChecks(); renderDashboardChecks(); renderLogs(); }
  });

  // keyboard
  document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); openCmdK(); }
    if (e.key === 'Escape') {
      closeCmdK();
      if (qs('#aiChatModal.open')) qs('#aiChatModal').classList.remove('open');
      if (qs('#connectRepoModal.open')) qs('#connectRepoModal').classList.remove('open');
    }
  });

  qs('#cmdkInput')?.addEventListener('input', e => renderCmdkResults(e.target.value));
  qs('#cmdkOverlay')?.addEventListener('click', e => { if (e.target === qs('#cmdkOverlay')) closeCmdK(); });

  // theme toggle
  qs('#themeToggle')?.addEventListener('click', () => {
    const body = document.body;
    body.dataset.theme = body.dataset.theme === 'dark' ? 'light' : 'dark';
  });
});
