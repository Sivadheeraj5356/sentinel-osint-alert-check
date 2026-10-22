// OSINT alert QA for gated-verification pipelines: reviews alert payloads before
// they reach offline-first clients - missing geolocation, unverified sources on
// high-severity alerts, duplicates and heavy payloads that may strain 2G clients.
// Heuristic review of pasted lines. Pure functions, no DOM.
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.OsintAlertCheck = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  const GEO_RE = /^-?\d{1,2}(\.\d+)?\s*,\s*-?\d{1,3}(\.\d+)?$/;

  function parseLines(input) {
    const alerts = [];
    const skipped = [];
    input.split('\n').forEach((raw, i) => {
      const line = raw.trim();
      if (!line) return;
      const p = raw.split('|').map((s) => s.trim());
      if (p.length >= 4 && p[0]) alerts.push({ severity: p[0], source: p[1], geo: p[2], text: p.slice(3).join(' | '), line: i + 1 });
      else skipped.push(i + 1);
    });
    return { alerts, skipped };
  }

  function check(input) {
    const { alerts, skipped } = typeof input === 'string' ? parseLines(input) : input;
    const findings = [];
    const push = (level, code, text) => findings.push({ level, code, text });
    const seen = {};

    alerts.forEach((a) => {
      const sev = a.severity.toLowerCase();
      const isHigh = /^(high|critical|severe)$/.test(sev);
      if (!GEO_RE.test(a.geo))
        push('warn', 'MISSING_GEOLOCATION', `Line ${a.line}: alert has no usable coordinates ("${a.geo || 'empty'}") - a threat alert without a location may be hard to act on; verify before pushing to clients.`);
      if (!a.source || /unknown|anonymous|unverified/i.test(a.source))
        push(isHigh ? 'error' : 'warn', 'SOURCE_UNVERIFIED', `Line ${a.line}: source is "${a.source || 'empty'}"${isHigh ? ' on a ' + sev + '-severity alert' : ''} - verify the source chain before this reaches a civilian in a conflict zone.`);
      if (isHigh && !/verified|confirmed|human.?review/i.test(a.text))
        push('warn', 'HIGH_SEVERITY_NO_REVIEW_HINT', `Line ${a.line}: ${sev}-severity alert carries no verification/review hint in its text - if a human gate has not seen this, verify before push.`);
      const norm = a.text.toLowerCase().replace(/\W+/g, ' ').trim();
      if (norm && seen[norm] !== undefined)
        push('warn', 'DUPLICATE_ALERT', `Line ${a.line}: text duplicates line ${seen[norm]} - duplicate pushes may erode trust in the alert feed; verify deduplication upstream.`);
      else if (norm) seen[norm] = a.line;
      if (a.text.length > 280)
        push('warn', 'PAYLOAD_HEAVY', `Line ${a.line}: alert text is ${a.text.length} chars - long payloads may strain offline-first clients on slow links; verify size budget.`);
    });

    if (skipped.length) push('warn', 'UNPARSED', `Line(s) ${skipped.join(', ')} skipped - expected severity | source | lat,lon | text.`);
    if (alerts.length && !findings.some((f) => f.level !== 'ok'))
      push('ok', 'ALERTS_WELL_FORMED', `${alerts.length} alert(s) passed these heuristics - presence of geolocation, named sources and dedupe only; truth of the underlying intel is out of scope.`);
    return { findings, stats: { alerts: alerts.length, skipped: skipped.length } };
  }
  return { parseLines, check };
});
