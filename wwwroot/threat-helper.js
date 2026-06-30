// Shared Threat Ingestion & Normalization Module
// Ensures consistent parsing between client JSON uploads, DB queries, and iframe message portals.

(function (window) {
  'use strict';

  /**
   * Normalizes raw threat records (from either flat array or units envelope,
   * handles both camelCase and PascalCase properties).
   * @param {Object|Array} data Raw input data
   * @returns {Array} List of normalized threat objects
   */
  function normalizeThreatData(data) {
    let records = data;
    if (!Array.isArray(data) && data && Array.isArray(data.units)) {
      records = data.units;
    }
    if (!Array.isArray(records)) return [];

    return records.map(item => {
      if (!item) return null;
      const unitId = item.unitId || item.UnitId;
      if (!unitId) return null;

      // Normalize threat count/level value
      let threatsVal = null;
      if (item.threats !== undefined && item.threats !== null) {
        threatsVal = Number(item.threats);
      } else if (item.threatLevel !== undefined && item.threatLevel !== null) {
        threatsVal = Number(item.threatLevel);
      } else if (item.ThreatLevel !== undefined && item.ThreatLevel !== null) {
        threatsVal = Number(item.ThreatLevel);
      }

      return {
        unitId:    unitId,
        threats:   isNaN(threatsVal) || threatsVal === null ? null : threatsVal,
        score:     item.score !== undefined ? item.score : (item.Score !== undefined ? item.Score : null),
        shortTerm: item.shortTerm !== undefined ? item.shortTerm : (item.ShortTerm !== undefined ? item.ShortTerm : null),
        longTerm:  item.longTerm !== undefined ? item.longTerm : (item.LongTerm !== undefined ? item.LongTerm : null),
        status:    item.status !== undefined ? item.status : (item.Status !== undefined ? item.Status : null),
        details:   item.details !== undefined ? item.details : (item.Details !== undefined ? item.Details : [])
      };
    }).filter(Boolean);
  }

  /**
   * Normalizes incoming threat data and updates targetMap (in-place).
   * Runs redraw and empty state callbacks after application.
   * @param {Object|Array} data Raw input data
   * @param {Object} targetMap The in-memory threatData map to update
   * @param {Function} redrawCb Callback to redraw Konva stage/zones
   * @param {Function} emptyStateCb Callback to check and update empty state display
   */
  function applyThreatData(data, targetMap, redrawCb, emptyStateCb) {
    if (!targetMap) return;
    const normalized = normalizeThreatData(data);
    normalized.forEach(item => {
      targetMap[item.unitId] = item;
    });

    if (typeof redrawCb === 'function') redrawCb();
    if (typeof emptyStateCb === 'function') emptyStateCb();
  }

  // Export to window
  window.normalizeThreatData = normalizeThreatData;
  window.applyThreatData = applyThreatData;

})(window);
