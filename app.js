(function () {
  const $ = (id) => document.getElementById(id);
  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function run() {
    const { findings, stats } = OsintAlertCheck.check($('alerts').value);
    $('findings').innerHTML = findings.map((f) =>
      `<li class="${f.level}"><span class="code">${esc(f.code)}</span><br>${esc(f.text)}</li>`).join('');
    $('stats').textContent = `${stats.alerts} alert(s) reviewed`;
    $('results').classList.remove('hidden');
  }
  $('run').addEventListener('click', run);
})();
