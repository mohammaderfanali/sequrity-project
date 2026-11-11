/* dynAn browser behaviour.
 *
 * Scope is deliberately narrow: tab switching, following a live run's event
 * stream, and jumping from a finding to the diff region it references.
 *
 * No status, severity or verdict is computed here. Everything displayed comes
 * from the server, which reads it from the canonical run model - the same one
 * the CLI renders.
 */
(function () {
  'use strict';

  // ------------------------------------------------------------ tabs

  function initTabs() {
    const tabs = document.querySelector('.tabs');
    if (!tabs) return;

    const buttons = Array.from(tabs.querySelectorAll('button[data-tab]'));
    const panels = Array.from(document.querySelectorAll('.tabpanel[data-panel]'));

    function activate(name, push) {
      buttons.forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
      panels.forEach((p) => { p.hidden = p.dataset.panel !== name; });
      if (push) history.replaceState(null, '', '#' + name);
    }

    buttons.forEach((button) => {
      button.addEventListener('click', () => activate(button.dataset.tab, true));
    });

    const initial = location.hash.replace('#', '');
    activate(buttons.some((b) => b.dataset.tab === initial) ? initial : buttons[0].dataset.tab, false);
  }

  // ------------------------------------------- finding -> diff navigation

  function initDiffLinks() {
    document.querySelectorAll('[data-goto-diff]').forEach((link) => {
      link.addEventListener('click', (event) => {
        event.preventDefault();
        const target = link.dataset.gotoDiff;

        const tabButton = document.querySelector('button[data-tab="diff"]');
        if (tabButton) tabButton.click();

        // Match on the patched-side line reference the correlation recorded.
        const cell = Array.from(document.querySelectorAll('td.src[data-line]'))
          .find((td) => td.dataset.line === target);

        if (cell) {
          document.querySelectorAll('tr.marked').forEach((tr) => tr.classList.remove('marked'));
          cell.closest('tr').classList.add('marked');
          cell.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
      });
    });
  }

  // ------------------------------------------------------- live progress

  function followRun(runId, options) {
    const { panel, label, feed, status, link, onEnd } = options || {};
    if (panel) panel.hidden = false;
    if (label) label.textContent = runId;
    if (status) status.textContent = 'running...';

    const source = new EventSource(`/api/v1/runs/${encodeURIComponent(runId)}/events`);
    let lastStage = '';

    source.addEventListener('progress', (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch (_) { return; }

      if (feed) {
        const line = document.createElement('div');
        line.className = 'line ' + (data.level || 'info') +
          (data.state === 'completed' ? ' done' : '');

        const stage = document.createElement('span');
        stage.className = 'stage';
        stage.textContent = data.stage || '';

        const message = document.createElement('span');
        message.className = 'msg';
        // textContent, not innerHTML: event text includes target output.
        message.textContent = data.message || '';

        line.appendChild(stage);
        line.appendChild(message);
        feed.appendChild(line);
        feed.scrollTop = feed.scrollHeight;
      }

      if (data.stage) lastStage = data.stage;
      if (status) {
        const counts = (data.data && data.data.total)
          ? ` (${data.data.current}/${data.data.total})`
          : '';
        status.textContent = `${lastStage}${counts}`;
      }
    });

    function finish() {
      source.close();
      if (status) status.textContent = 'finished';
      if (link) {
        link.hidden = false;
        link.href = `/runs/${runId}`;
      }
      if (typeof onEnd === 'function') onEnd();
    }

    source.addEventListener('end', finish);
    source.addEventListener('error', () => {
      // The stream also ends when the server closes it after the final event.
      if (source.readyState === EventSource.CLOSED) finish();
    });

    return source;
  }

  window.dynan = { followRun };

  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initDiffLinks();
  });
})();
