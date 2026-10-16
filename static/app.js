const session = {scanned: 0, vulnerable: 0, findings: 0, sourceFindings: 0, recent: []};
let riskChart = null;

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === `page-${name}`));
  document.querySelectorAll('.nav-link').forEach(b => b.classList.toggle('active', b.dataset.page === name));
  const titles = {dashboard:'Security overview', scanner:'Package scanner', source:'Source code review'};
  document.getElementById('page-title').textContent = titles[name] || 'Dashboard';
  if (name === 'analytics') loadAnalytics();
}
document.querySelectorAll('[data-page]').forEach(b => b.addEventListener('click', () => showPage(b.dataset.page)));
document.querySelectorAll('[data-go]').forEach(b => b.addEventListener('click', () => showPage(b.dataset.go)));

function setBusy(id, busy) { document.getElementById(id).classList.toggle('hidden', !busy); }
function showError(id, message) { const el = document.getElementById(id); el.textContent = message; el.classList.remove('hidden'); }
function hideError(id) { document.getElementById(id).classList.add('hidden'); }
function esc(value) { return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function riskClass(level) {
  if (['No known findings','Low'].includes(level)) return 'good';
  if (['Review','Medium'].includes(level)) return 'warn';
  if (['High','Critical'].includes(level)) return 'bad';
  return 'unknown';
}
function updateMetrics() {
  document.getElementById('metric-scanned').textContent = session.scanned;
  document.getElementById('metric-vulnerable').textContent = session.vulnerable;
  document.getElementById('metric-findings').textContent = session.findings;
  document.getElementById('metric-source').textContent = session.sourceFindings;
  const host = document.getElementById('recent-scans');
  if (!session.recent.length) return;
  host.className = '';
  host.innerHTML = session.recent.slice(0,5).map(r => `<div class="finding"><strong>${esc(r.name)} <span class="pill ${riskClass(r.risk_level)}">${esc(r.risk_level)}</span></strong><p>Version ${esc(r.version)} · ${r.vulnerability_count} known finding(s)</p></div>`).join('');
}
function renderScanResults(results) {
  const area = document.getElementById('scan-results');
  area.classList.remove('hidden');
  area.innerHTML = results.map(r => {
    const vulns = (r.vulnerabilities || []).map(v => `<div class="finding"><strong>${esc(v.id)} · ${esc(v.severity)}</strong><p>${esc(v.summary)}</p><a href="${esc(v.details_url)}" target="_blank" rel="noopener noreferrer">View advisory ↗</a></div>`).join('');
    const notes = (r.notes || []).map(n => `<div class="notice">${esc(n)}</div>`).join('');
    const metadata = r.metadata || {};
    return `<article class="result-card"><div class="result-top"><div><h3>${esc(r.name)} <span class="pill">${esc(r.version)}</span></h3><p>${esc(metadata.summary || 'Package metadata unavailable')}</p></div><span class="pill ${riskClass(r.risk_level)}">${esc(r.risk_level)}</span></div><div class="result-stats"><div><small>Known vulnerabilities</small><strong>${r.vulnerability_count}</strong></div><div><small>Demo risk score</small><strong>${r.risk_score === null ? 'N/A' : r.risk_score + '/100'}</strong></div><div><small>Lookup status</small><strong style="font-size:12px">${esc(r.status)}</strong></div></div><div class="table-wrap"><table><tbody><tr><th>License</th><td>${esc(metadata.license || 'Not available')}</td><th>Requires Python</th><td>${esc(metadata.requires_python || 'Not available')}</td></tr><tr><th>Author</th><td>${esc(metadata.author || 'Not available')}</td><th>Latest on PyPI</th><td>${esc(metadata.latest_version || 'Not available')}</td></tr></tbody></table></div>${vulns || '<div class="notice">No vulnerability records were returned for this query. This does not prove the package is safe.</div>'}${notes}</article>`;
  }).join('');
  results.forEach(r => {
    session.scanned++;
    session.vulnerable += r.vulnerability_count > 0 ? 1 : 0;
    session.findings += r.vulnerability_count;
    session.recent.unshift(r);
  });
  updateMetrics();
}
async function submitScan(form, endpoint) {
  hideError('scan-error'); setBusy('scan-loading', true);
  document.getElementById('scan-results').classList.add('hidden');
  try {
    const response = await fetch(endpoint, {method:'POST', body:new FormData(form)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Scan failed.');
    renderScanResults(data.results || []);
  } catch (e) { showError('scan-error', e.message || 'Could not connect to the server.'); }
  finally { setBusy('scan-loading', false); }
}
document.getElementById('single-form').addEventListener('submit', e => {e.preventDefault(); submitScan(e.currentTarget, '/api/scan');});
document.getElementById('requirements-form').addEventListener('submit', e => {e.preventDefault(); submitScan(e.currentTarget, '/api/scan');});
document.querySelectorAll('[data-tab]').forEach(tab => tab.addEventListener('click', () => {
  document.querySelectorAll('[data-tab]').forEach(t => t.classList.toggle('active', t === tab));
  document.getElementById('single-form').classList.toggle('hidden', tab.dataset.tab !== 'single');
  document.getElementById('requirements-form').classList.toggle('hidden', tab.dataset.tab !== 'requirements');
}));

document.getElementById('source-form').addEventListener('submit', async e => {
  e.preventDefault(); hideError('source-error'); setBusy('source-loading', true);
  document.getElementById('source-results').classList.add('hidden');
  try {
    const response = await fetch('/api/source-check', {method:'POST', body:new FormData(e.currentTarget)});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Source check failed.');
    if (!data.ok) throw new Error(data.error || 'Could not parse source.');
    const findings = data.findings || [];
    session.sourceFindings += findings.length; updateMetrics();
    document.getElementById('source-results').innerHTML = `<article class="source-result"><h3>Source review summary</h3><p>${esc(data.message)}</p><div class="result-stats"><div><small>Imports found</small><strong>${(data.imports||[]).length}</strong></div><div><small>Pattern matches</small><strong>${findings.length}</strong></div><div><small>Review status</small><strong>${findings.length ? 'Manual review' : 'No patterns matched'}</strong></div></div><p><strong>Imports:</strong> ${esc((data.imports||[]).join(', ') || 'None detected')}</p>${findings.length ? findings.map(f=>`<div class="code-finding"><strong>Line ${esc(f.line)} · ${esc(f.pattern)}</strong><code>${esc(f.snippet)}</code></div>`).join('') : '<div class="notice">No selected patterns were detected. This does not prove the file is benign.</div>'}</article>`;
    document.getElementById('source-results').classList.remove('hidden');
  } catch (err) { showError('source-error', err.message || 'Could not connect to the server.'); }
  finally { setBusy('source-loading', false); }
});

async function loadAnalytics() {
  try {
    const response = await fetch('/api/analytics');
    const d = await response.json();
    document.getElementById('analytics-count').textContent = d.rows.length;
    document.getElementById('analytics-mean').textContent = d.central_tendency.risk_score.mean;
    document.getElementById('analytics-median').textContent = d.central_tendency.risk_score.median;
    const names = {dependency_count:'Dependency count', vulnerability_count:'Vulnerability count', suspicious_api_count:'Suspicious API count', risk_score:'Risk score'};
    document.getElementById('stats-table').innerHTML = Object.entries(d.descriptive).map(([k,v])=>`<tr><td>${names[k]}</td><td>${v.mean}</td><td>${v.median}</td><td>${v.std}</td></tr>`).join('');
    document.getElementById('central-table').innerHTML = Object.entries(d.central_tendency).map(([k,v])=>`<tr><td>${names[k]}</td><td>${v.mean}</td><td>${v.median}</td><td>${esc((v.mode||[]).join(', ') || '—')}</td></tr>`).join('');
    const cols = d.correlation.columns;
    let html = '<table class="correlation-table"><thead><tr><th>Feature</th>'+cols.map(c=>`<th>${names[c]}</th>`).join('')+'</tr></thead><tbody>';
    d.correlation.matrix.forEach((row,i)=>{html += `<tr><th>${names[cols[i]]}</th>`+row.map(v=>{const n=Number(v);const opacity=Math.min(0.75,Math.abs(n)*0.7);const bg=n>=0?`rgba(42,155,113,${opacity})`:`rgba(218,83,97,${opacity})`;return `<td><span class="corr-cell" style="background:${bg};color:${Math.abs(n)>.55?'white':'#34445e'}">${n.toFixed(2)}</span></td>`}).join('')+'</tr>';});
    html += '</tbody></table>';
    document.getElementById('correlation-table').innerHTML = html;
    const a = d.anova;
    document.getElementById('anova-summary').innerHTML = `<strong>One-way ANOVA · risk score by risk level</strong><div class="anova-number">F = ${a.f_statistic === null ? 'N/A' : a.f_statistic}</div><p>p-value: <strong>${a.p_value === null ? 'N/A' : a.p_value}</strong></p><p>${esc(a.note)}</p>`;
    const labels = Object.keys(d.risk_distribution);
    const values = labels.map(k=>d.risk_distribution[k]);
    const ctx = document.getElementById('risk-chart');
    if (riskChart) riskChart.destroy();
    riskChart = new Chart(ctx, {type:'bar',data:{labels,datasets:[{label:'Sample packages',data:values,borderWidth:0,borderRadius:6,backgroundColor:['#4b75f2','#a183e6','#e7b34e','#e36a78']}]},options:{responsive:true,plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0},grid:{color:'#edf0f5'}},x:{grid:{display:false}}}}});
  } catch (e) { console.error('Analytics load failed', e); }
}
updateMetrics();
