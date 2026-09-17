/* Copy buttons. The page is complete without this file. */
(function () {
  function fallback(text) { var t = document.createElement('textarea'); t.value = text; t.setAttribute('readonly', ''); t.style.position = 'fixed'; t.style.opacity = '0'; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch (e) { } document.body.removeChild(t); }
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]'); if (!b) return;
    var text = b.getAttribute('data-copy'), label = b.querySelector('.copy-label') || b, old = label.textContent;
    var done = function () { label.textContent = 'Copied'; b.classList.add('copied'); setTimeout(function () { label.textContent = old; b.classList.remove('copied'); }, 1600); };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () { fallback(text); done(); }); else { fallback(text); done(); }
  });
})();

/* Screenshot zoom: the link opens the full image; with <dialog> support it opens in place. */
(function () {
  var dlg = document.getElementById('zoom');
  if (!dlg || typeof dlg.showModal !== 'function') return;
  document.addEventListener('click', function (e) {
    if (e.target.closest('[data-zoom]')) { e.preventDefault(); dlg.showModal(); return; }
    if (dlg.open && dlg.contains(e.target)) dlg.close();
  });
})();

/* Latest release from GitHub: version label, install tarball and copy text. Links point at releases/latest, so they stay right without this. */
(function () {
  if (!window.fetch || !document.querySelector('[data-release-label], [data-release-tarball]')) return;
  fetch('https://api.github.com/repos/IluvatarLabs/blinddrop/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
    .then(function (r) { if (!r.ok) throw new Error('GitHub ' + r.status); return r.json(); })
    .then(function (rel) {
      var version = String(rel.tag_name || '').replace(/^v/, '');
      if (!version) return;
      document.querySelectorAll('[data-release-label]').forEach(function (el) { el.textContent = 'Release ' + version; });
      var tgz = (rel.assets || []).filter(function (a) { return /\.tgz$/.test(a.name); })[0];
      if (!tgz) return;
      document.querySelectorAll('[data-release-tarball]').forEach(function (el) { el.textContent = tgz.browser_download_url; });
      document.querySelectorAll('[data-copy-prefix]').forEach(function (el) { el.setAttribute('data-copy', el.getAttribute('data-copy-prefix') + tgz.browser_download_url); });
    })
    .catch(function () { });
})();
