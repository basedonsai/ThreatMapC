(function (window) {
  'use strict';

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, ch => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[ch]));
  }

  function parseScore(value) {
    if (value === null || value === undefined) return 0;
    const n = parseInt(String(value).replace(/,/g, '').trim(), 10);
    return isNaN(n) ? 0 : n;
  }

  function formatScore(value) {
    return parseScore(value).toLocaleString();
  }

  function getThreatType(item) {
    const type = (item?.threatType || item?.ThreatType || '').toUpperCase().trim();
    return type === 'LTT' ? 'ltt' : 'stt';
  }

  function filterThreatDetails(details, filter) {
    const rows = Array.isArray(details) ? details : [];
    if (filter === 'stt') return rows.filter(item => getThreatType(item) === 'stt');
    if (filter === 'ltt') return rows.filter(item => getThreatType(item) === 'ltt');
    return rows.slice();
  }

  function getScoreValue(item, ramType) {
    if (ramType === 'HSSC RAM') return item?.hsscScore || item?.HSSCScore || item?.mtoScore || item?.MTOScore || '0';
    if (ramType === 'Production RAM') return item?.productionScore || item?.ProductionScore || item?.mtoScore || item?.MTOScore || '0';
    return item?.mtoScore || item?.MTOScore || '0';
  }

  function getRamCode(item, ramType) {
    if (ramType === 'HSSC RAM') return item?.hsscRAM || item?.HSSCRAM || item?.primaryRAM || item?.PrimaryRAM || 'E0';
    if (ramType === 'Production RAM') return item?.productionRAM || item?.ProductionRAM || item?.primaryRAM || item?.PrimaryRAM || 'E0';
    return item?.primaryRAM || item?.PrimaryRAM || 'E0';
  }

  function getRamStyle(ram) {
    const r = String(ram || '').toUpperCase().trim();
    if (['D5', 'D4', 'E5', 'E4', 'C5', 'C4', 'D3', 'E3'].includes(r)) return { bg: '#d50000', text: '#ffffff' };
    if (['B5', 'B4', 'C3', 'C2', 'D2', 'E2', 'A5', 'A4'].includes(r)) return { bg: '#ffeb3b', text: '#000000' };
    if (['B3', 'B2', 'A3', 'A2', 'C1'].includes(r)) return { bg: '#0d47a1', text: '#ffffff' };
    return { bg: '#cfd8dc', text: '#37474f' };
  }

  function allThreatRows(threatData) {
    const rows = [];
    Object.entries(threatData || {}).forEach(([unitId, unit]) => {
      const details = Array.isArray(unit?.details) ? unit.details : [];
      details.forEach(item => rows.push({ unitId, item }));
    });
    return rows;
  }

  function buildThreatSummary(threatData, ramType, filter) {
    const rows = allThreatRows(threatData);
    const filteredRows = filterThreatDetails(rows.map(r => r.item), filter);
    const filteredPairs = rows.filter(r => filteredRows.includes(r.item));
    const sttCount = rows.filter(r => getThreatType(r.item) === 'stt').length;
    const lttCount = rows.filter(r => getThreatType(r.item) === 'ltt').length;
    const unitScores = {};
    let totalScore = 0;

    filteredPairs.forEach(({ unitId, item }) => {
      const score = parseScore(getScoreValue(item, ramType));
      totalScore += score;
      unitScores[unitId] = (unitScores[unitId] || 0) + score;
    });

    const highRiskUnits = Object.entries(unitScores)
      .map(([unitId, score]) => ({ unitId, score }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);

    return {
      totalThreats: filteredPairs.length,
      totalScore,
      sttCount,
      lttCount,
      highRiskUnits,
      rows: filteredPairs
    };
  }

  function renderFilterControls(activeFilter) {
    const filters = [
      ['all', 'All'],
      ['stt', 'STT'],
      ['ltt', 'LTT']
    ];
    return `<div style="display:flex;gap:6px;padding:8px 10px;border-bottom:1px solid #ddd;background:#fafafa;">
      ${filters.map(([value, label]) => {
        const active = value === activeFilter;
        return `<button type="button" data-threat-filter="${value}" style="border:1px solid ${active ? '#0b4d6b' : '#c8cdd2'};background:${active ? '#0b4d6b' : '#fff'};color:${active ? '#fff' : '#333'};border-radius:3px;padding:4px 9px;font-size:11px;font-weight:600;cursor:pointer;">${label}</button>`;
      }).join('')}
    </div>`;
  }

  function renderThreatTable(rows, ramType) {
    if (!rows.length) {
      return '<div style="color:#888;font-size:12px;text-align:center;padding:28px 10px;">No threats match this filter</div>';
    }

    const body = rows.map(({ unitId, item }) => {
      const ram = getRamCode(item, ramType);
      const ramStyle = getRamStyle(ram);
      const threatUrl = (item.threatURL || item.ThreatURL || '').trim();
      const threatId = escapeHtml(item.threatID || item.ThreatID || '');
      const idCell = threatUrl
        ? `<a href="${escapeHtml(threatUrl)}" target="_blank" style="color:#0288d1;text-decoration:underline;font-weight:bold;">${threatId}</a>`
        : threatId;
      const tagVal = (item.tag || item.Tag || '').trim();
      const tagCell = tagVal
        ? `<a href="https://inhydvmimi1:4433/DataRetrieve/AssetDetails.aspx?tag=${encodeURIComponent(tagVal)}" target="_blank" style="color:#0288d1;text-decoration:underline;">${escapeHtml(tagVal)}</a>`
        : 'Unit Level';

      return `<tr style="background:#fff;border-bottom:1px solid #eee;">
        <td style="padding:6px 8px;border:1px solid #ddd;font-weight:600;">${escapeHtml(unitId)}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;">${idCell}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;">${tagCell}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;font-size:10.5px;line-height:1.3;max-width:240px;word-wrap:break-word;white-space:normal;">${escapeHtml(item.initiativeName || item.InitiativeName || '')}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;text-align:right;font-weight:600;">${formatScore(getScoreValue(item, ramType))}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;text-align:center;font-weight:bold;background:${ramStyle.bg};color:${ramStyle.text};">${escapeHtml(ram)}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;text-align:center;">${escapeHtml((item.threatType || item.ThreatType || 'STT').toUpperCase())}</td>
        <td style="padding:6px 8px;border:1px solid #ddd;text-align:center;color:#555;">${escapeHtml((item.threatDiscipline || item.ThreatDiscipline || '').split(':')[0])}</td>
      </tr>`;
    }).join('');

    return `<div style="padding:8px;overflow-x:auto;">
      <table class="pe-aim-table" style="width:100%;border-collapse:collapse;font-size:11px;text-align:left;font-family:'Segoe UI',Arial,sans-serif;">
        <thead>
          <tr style="background:#0b4d6b;color:#fff;font-weight:600;text-transform:uppercase;font-size:10px;letter-spacing:0.5px;">
            <th style="padding:8px;border:1px solid #ddd;">Unit</th>
            <th style="padding:8px;border:1px solid #ddd;">ID</th>
            <th style="padding:8px;border:1px solid #ddd;">Tag</th>
            <th style="padding:8px;border:1px solid #ddd;">Initiative name</th>
            <th style="padding:8px;border:1px solid #ddd;text-align:right;">Score</th>
            <th style="padding:8px;border:1px solid #ddd;text-align:center;">RAM</th>
            <th style="padding:8px;border:1px solid #ddd;text-align:center;">Type</th>
            <th style="padding:8px;border:1px solid #ddd;text-align:center;">Discipline</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;
  }

  function renderOverallThreatPanel(threatData, filter, options) {
    const ramType = options?.ramType || 'Overall RAM';
    const summary = buildThreatSummary(threatData, ramType, filter);
    const highRisk = summary.highRiskUnits.length
      ? summary.highRiskUnits.map((u, idx) => `<div style="display:flex;justify-content:space-between;padding:3px 0;"><span>${idx + 1}. ${escapeHtml(u.unitId)}</span><strong>${formatScore(u.score)}</strong></div>`).join('')
      : '<div style="color:#888;font-size:12px;">No threat scores available</div>';

    return `${renderFilterControls(filter)}
      <div style="padding:10px;border-bottom:1px solid #ddd;background:#f5f6f7;">
        <div style="font-weight:bold;font-size:13px;color:#333;margin-bottom:8px;">Overall Threat Summary</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;font-size:12px;">
          <div>Total Threats: <strong>${summary.totalThreats}</strong></div>
          <div>Total RAM: <strong>${formatScore(summary.totalScore)}</strong></div>
          <div>Short-Term: <strong>${summary.sttCount}</strong></div>
          <div>Long-Term: <strong>${summary.lttCount}</strong></div>
        </div>
        <div style="margin-top:10px;font-size:12px;">
          <div style="font-weight:700;color:#333;margin-bottom:4px;">Highest Risk Units</div>
          ${highRisk}
        </div>
      </div>
      ${renderThreatTable(summary.rows, ramType)}`;
  }

  function renderZoneThreatPanel(unitId, unitData, filter, options) {
    const ramType = options?.ramType || 'Overall RAM';
    const details = filterThreatDetails(unitData?.details || [], filter);
    const rows = details.map(item => ({ unitId, item }));
    const score = rows.reduce((sum, row) => sum + parseScore(getScoreValue(row.item, ramType)), 0);

    return `${renderFilterControls(filter)}
      <div style="padding:10px;border-bottom:1px solid #ddd;background:#f5f6f7;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <span style="font-weight:bold;font-size:13px;color:#333;">Zone ${escapeHtml(unitId)}</span>
          <span style="font-size:11px;background:#e8edf2;border:1px solid #ccd4dc;padding:2px 8px;border-radius:3px;color:#555;font-weight:600;">${escapeHtml(ramType)}</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px;font-size:12px;">
          <div>Threat Count: <strong>${rows.length}</strong></div>
          <div>Score: <strong>${formatScore(score)}</strong></div>
        </div>
      </div>
      ${renderThreatTable(rows, ramType)}`;
  }

  function resetToOverallView(state) {
    if (state) {
      state.selectedZone = null;
      state.panelMode = 'overall';
    }
  }

  window.ThreatMapSidebar = {
    buildThreatSummary,
    filterThreatDetails,
    renderOverallThreatPanel,
    renderZoneThreatPanel,
    resetToOverallView
  };
})(window);
