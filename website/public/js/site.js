/* Static-site hydration.
 *
 * The site ships fully rendered HTML, so it works with JavaScript disabled and
 * with no server logic at all. This script only refreshes the parts that go
 * stale between deploys: the version badge, the download card and the changelog
 * list. Everything comes from ./data/releases.json, a static file produced at
 * package time, so there is no runtime API and nothing to authenticate.
 *
 * If the fetch fails (offline, file:// preview, missing file) the baked HTML
 * stays exactly as it is -- a failed refresh never blanks the page.
 */
(function () {
  'use strict';

  var FEED = '/data/releases.json';
  var REPO = 'https://github.com/sudfiona/NovaProtect';

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function formatDate(value) {
    if (!value) return '';
    return String(value);
  }

  function renderNotes(container, notes) {
    container.textContent = '';
    // Release bodies are plain text with newlines; keep them as text so a
    // future release note can never inject markup.
    var lines = String(notes || '').split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      if (i > 0) container.appendChild(document.createElement('br'));
      container.appendChild(document.createTextNode(lines[i]));
    }
  }

  function renderChangelog(list, releases) {
    list.textContent = '';
    if (!releases.length) {
      list.appendChild(el('p', 'empty-state', '暂无客户端更新日志。'));
      return;
    }
    releases.forEach(function (release) {
      var card = el('article', 'surface announcement');

      var meta = el('div', 'announcement-meta');
      meta.appendChild(el('span', release.prerelease ? 'status status-muted' : 'status status-ok',
        release.prerelease ? '预发布' : '正式版'));
      var time = el('time', null, formatDate(release.publishedAt));
      meta.appendChild(time);
      card.appendChild(meta);

      card.appendChild(el('h2', null, '客户端 ' + release.version));
      var body = el('p', 'announcement-body');
      renderNotes(body, release.notes);
      card.appendChild(body);

      if (release.pageUrl) {
        var hint = el('p', 'field-hint');
        var link = el('a', null, '在 GitHub 查看该版本');
        link.href = release.pageUrl;
        link.rel = 'noopener';
        hint.appendChild(link);
        card.appendChild(hint);
      }
      list.appendChild(card);
    });
  }

  function fillDownload(releases) {
    var latest = releases[0];
    if (!latest) return;
    document.querySelectorAll('[data-latest-version]').forEach(function (node) {
      node.textContent = latest.version;
    });
    document.querySelectorAll('[data-latest-date]').forEach(function (node) {
      node.textContent = formatDate(latest.publishedAt);
    });
  }

  function hydrate() {
    if (!document.querySelector('[data-changelog], [data-latest-version]')) return;
    fetch(FEED, { cache: 'no-store', headers: { Accept: 'application/json' } })
      .then(function (response) {
        if (!response.ok) throw new Error('feed ' + response.status);
        return response.json();
      })
      .then(function (releases) {
        if (!Array.isArray(releases) || !releases.length) return;
        var list = document.querySelector('[data-changelog]');
        if (list) renderChangelog(list, releases);
        fillDownload(releases);
      })
      .catch(function () {
        // Baked HTML stays. A stale-but-real page beats an empty one.
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', hydrate);
  } else {
    hydrate();
  }
})();
