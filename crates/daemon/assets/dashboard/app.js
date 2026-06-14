// hushwarren dashboard — plain JS, no framework, no CDN, offline-safe.
// Token delivery: fragment (#token=<hex>) → sessionStorage → stripped.

(function () {
  'use strict';

  // ── Token bootstrap ─────────────────────────────────────────────────────────

  var TOKEN_KEY = 'hush_token';

  function bootstrap_token() {
    var hash = window.location.hash;
    if (hash && hash.startsWith('#token=')) {
      var tok = hash.slice('#token='.length);
      if (tok.length === 64) {
        sessionStorage.setItem(TOKEN_KEY, tok);
        // Strip fragment — never let it appear in server logs or referrers.
        history.replaceState(null, '', window.location.pathname + window.location.search);
      }
    }
  }

  function get_token() {
    return sessionStorage.getItem(TOKEN_KEY) || '';
  }

  // ── API helpers ─────────────────────────────────────────────────────────────

  function api(path, opts) {
    var tok = get_token();
    var headers = Object.assign({ 'Authorization': 'Bearer ' + tok }, opts && opts.headers);
    return fetch(path, Object.assign({}, opts, { headers: headers }))
      .then(function (r) {
        if (!r.ok) return r.json().then(function (e) { throw new Error(e.error || r.statusText); });
        return r.json();
      });
  }

  function api_post(path, body) {
    return api(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  // ── DOM helpers ─────────────────────────────────────────────────────────────

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) { e[k] = attrs[k]; });
    if (children) children.forEach(function (c) { e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return e;
  }

  function set_html(id, html) {
    var node = document.getElementById(id);
    if (node) node.innerHTML = html;
  }

  function badge(text, cls) {
    return '<span class="badge badge-' + cls + '">' + esc(text) + '</span>';
  }

  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Tab routing ─────────────────────────────────────────────────────────────

  var tabs = document.querySelectorAll('.tab');
  var panels = document.querySelectorAll('.panel');

  tabs.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var id = btn.dataset.tab;
      tabs.forEach(function (t) { t.classList.remove('active'); });
      panels.forEach(function (p) { p.classList.remove('active'); });
      btn.classList.add('active');
      var panel = document.getElementById(id);
      if (panel) panel.classList.add('active');
      load_tab(id);
    });
  });

  // ── Status panel ────────────────────────────────────────────────────────────

  function load_status() {
    api('/v0/status').then(function (d) {
      var state_badge = d.state === 'filtering'
        ? badge('Filtering', 'ok')
        : (d.state === 'snoozed' ? badge('Snoozed', 'warn') : badge(d.state, 'off'));

      var rows = [
        ['Guard state', state_badge],
        ['Version', esc(d.version)],
        ['Uptime', fmt_secs(d.uptime_secs)],
        ['Queries (total)', esc(d.counters.queries_total)],
        ['Blocked (total)', esc(d.counters.blocked_total)],
        ['Forwarded (total)', esc(d.counters.forwarded_total)],
        ['Rules loaded', esc(d.rules.block_count)],
        ['Query log mode', badge(d.privacy.query_log, d.privacy.query_log === 'off' ? 'off' : 'ok')],
      ];

      var html = '<div class="card">';
      rows.forEach(function (r) {
        html += '<div class="card-row"><span class="card-label">' + r[0] + '</span><span class="card-value">' + r[1] + '</span></div>';
      });
      html += '</div>';
      set_html('status-content', html);
    }).catch(function (e) {
      set_html('status-content', '<p class="err">Error: ' + esc(e.message) + '</p>');
    });
  }

  function fmt_secs(s) {
    var h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + sec + 's';
  }

  // ── Recently blocked panel ──────────────────────────────────────────────────

  function load_blocked() {
    api('/v0/queries/recent?n=100&blocked_only=true').then(function (d) {
      if (d.log_mode === 'off') {
        set_html('blocked-content', '<p>Query log is off — no blocked queries to show.</p>');
        return;
      }
      if (!d.queries || d.queries.length === 0) {
        set_html('blocked-content', '<p>No blocked queries in the recent ring.</p>');
        return;
      }
      var html = '<div class="card"><table><thead><tr><th>Domain</th><th>Reason</th><th>Time</th><th></th></tr></thead><tbody>';
      d.queries.forEach(function (q) {
        var ts = new Date(q.ts_unix_ms).toLocaleTimeString();
        html += '<tr>'
          + '<td>' + esc(q.qname) + '</td>'
          + '<td>' + esc(q.reason) + '</td>'
          + '<td>' + esc(ts) + '</td>'
          + '<td><button class="allow-btn" data-domain="' + esc(q.qname) + '">Allow</button></td>'
          + '</tr>';
      });
      html += '</tbody></table></div>';
      set_html('blocked-content', html);

      // Wire allow buttons.
      document.querySelectorAll('#blocked-content .allow-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var domain = btn.dataset.domain;
          api_post('/v0/allow', { domain: domain }).then(function () {
            btn.textContent = 'Allowed';
            btn.disabled = true;
          }).catch(function (e) {
            alert('Allow failed: ' + e.message);
          });
        });
      });
    }).catch(function (e) {
      set_html('blocked-content', '<p class="err">Error: ' + esc(e.message) + '</p>');
    });
  }

  // ── Insights panel ──────────────────────────────────────────────────────────

  function load_insights() {
    Promise.all([
      api('/v0/stats/top?n=10&hours=168').catch(function () { return null; }),
      api('/v0/stats/history?hours=168&bucket=86400').catch(function () { return null; })
    ]).then(function (results) {
      var top = results[0];
      var hist = results[1];
      var html = '';

      if (!top || top.log_mode === 'off') {
        html += '<div class="card"><p>Insights unavailable: query log is off.</p></div>';
      } else {
        html += '<div class="card"><h3 style="margin-bottom:0.75rem;font-size:0.95rem;color:#3f3f46">Top Blocked (7 days)</h3>';
        if (!top.blocked || top.blocked.length === 0) {
          html += '<p>No data yet.</p>';
        } else {
          html += '<table><thead><tr><th>Domain</th><th>Count</th></tr></thead><tbody>';
          top.blocked.forEach(function (item) {
            html += '<tr><td>' + esc(item.qname) + '</td><td>' + esc(item.count) + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        html += '</div>';
      }

      if (hist && hist.buckets && hist.buckets.length > 0) {
        html += '<div class="card"><h3 style="margin-bottom:0.75rem;font-size:0.95rem;color:#3f3f46">Daily totals</h3>';
        html += '<table><thead><tr><th>Date</th><th>Total</th><th>Blocked</th></tr></thead><tbody>';
        hist.buckets.forEach(function (b) {
          var d = new Date(b.ts).toLocaleDateString();
          html += '<tr><td>' + esc(d) + '</td><td>' + esc(b.total) + '</td><td>' + esc(b.blocked) + '</td></tr>';
        });
        html += '</tbody></table></div>';
      }

      if (!html) html = '<p>No data available yet.</p>';
      set_html('insights-content', html);
    });
  }

  // ── Lists panel ─────────────────────────────────────────────────────────────

  function load_lists() {
    api('/v0/lists').then(function (d) {
      var html = '<div class="card"><div class="card-row"><span class="card-label">Preset</span><span class="card-value">' + esc(d.preset) + '</span></div></div>';
      html += '<div class="card"><table><thead><tr><th>Name</th><th>Category</th><th>Rules</th><th>License</th><th>Attribution</th></tr></thead><tbody>';
      (d.sources || []).forEach(function (s) {
        html += '<tr>'
          + '<td>' + esc(s.name) + '</td>'
          + '<td>' + esc(s.category || '—') + '</td>'
          + '<td>' + esc(s.rule_count != null ? s.rule_count : '—') + '</td>'
          + '<td>' + esc(s.license || '—') + '</td>'
          + '<td style="font-size:0.8rem;color:#52525b">' + esc(s.attribution || '—') + '</td>'
          + '</tr>';
      });
      html += '</tbody></table></div>';
      set_html('lists-content', html);
    }).catch(function (e) {
      set_html('lists-content', '<p class="err">Error: ' + esc(e.message) + '</p>');
    });
  }

  // ── Privacy panel ───────────────────────────────────────────────────────────

  function load_privacy() {
    api('/v0/status').then(function (d) {
      var p = d.privacy;
      var toggles = [
        ['Browser DoH canary (use-application-dns.net → NXDOMAIN)', p.browser_doh_canary],
        ['CNAME chain inspection', p.cname_inspection],
        ['DoH bypass blocking', p.block_doh_bypass],
        ['Private Relay blocking', p.block_private_relay],
        ['RFC 8467 DoH padding', p.doh_padding],
        ['DNS rebinding protection', p.rebind_protection],
      ];

      var html = '<div class="card">';
      toggles.forEach(function (t) {
        html += '<div class="toggle-row">'
          + '<span class="toggle-desc">' + esc(t[0]) + '</span>'
          + '<span class="toggle-val">' + (t[1] ? badge('On', 'ok') : badge('Off', 'off')) + '</span>'
          + '</div>';
      });
      html += '<div class="toggle-row"><span class="toggle-desc">Query log mode</span><span class="toggle-val">' + badge(p.query_log, p.query_log === 'full' ? 'ok' : p.query_log === 'anonymous' ? 'warn' : 'off') + '</span></div>';
      html += '</div>';

      // Private Relay trade-off note (roadmap §2.2).
      html += '<div class="info-box">'
        + '<strong>iCloud Private Relay trade-off:</strong> '
        + 'Private Relay encrypts your DNS queries before they leave Apple devices, which is itself a privacy feature. '
        + 'Blocking it (block_private_relay=true) gives hushwarren visibility of those queries, but removes Apple\'s encryption layer. '
        + 'The default is off — we do not trade your privacy for our coverage.'
        + '</div>';

      // What DNS cannot do (roadmap §5 honesty block).
      html += '<div class="info-box" style="margin-top:0.5rem">'
        + '<strong>What DNS filtering cannot do:</strong> '
        + 'DNS-level blocking only prevents resolution — it does not block IP-direct connections, '
        + 'ads served from first-party domains, HTTPS content inspection, or traffic from apps '
        + 'that bypass the system resolver. hushwarren is not a firewall.'
        + '</div>';

      set_html('privacy-content', html);
    }).catch(function (e) {
      set_html('privacy-content', '<p class="err">Error: ' + esc(e.message) + '</p>');
    });
  }

  // ── Clients panel (WP13 Network Guard) ─────────────────────────────────────

  function load_clients() {
    api('/v0/clients?hours=24').then(function (d) {
      if (!d.log_clients_enabled) {
        var msg = d.explanation
          ? '<p>' + esc(d.explanation) + '</p>'
          : '<p>Per-client logging is off.</p>';
        // Router guidance block.
        msg += '<div class="info-box">'
          + '<strong>Network Guard — Router DHCP DNS setup:</strong> '
          + 'To protect every device on your network, configure your router\'s DHCP server to '
          + 'hand out this machine\'s LAN IP as the DNS server. '
          + 'Then enable <code>network_guard.enabled = true</code> and add the LAN IP to '
          + '<code>network_guard.bind</code> in the config. '
          + 'Also set <code>network_guard.log_clients = true</code> to see per-device stats here.'
          + '</div>';
        set_html('clients-content', msg);
        return;
      }

      if (!d.clients || d.clients.length === 0) {
        set_html('clients-content', '<p>No client data in the last 24 hours.</p>');
        return;
      }

      var html = '<div class="card"><table><thead><tr><th>Client IP</th><th>Hostname</th><th>Total</th><th>Blocked</th></tr></thead><tbody>';
      d.clients.forEach(function (c) {
        html += '<tr>'
          + '<td>' + esc(c.client) + '</td>'
          + '<td>' + (c.name ? esc(c.name) : '<span class="muted">—</span>') + '</td>'
          + '<td>' + esc(c.total) + '</td>'
          + '<td>' + esc(c.blocked) + '</td>'
          + '</tr>';
      });
      html += '</tbody></table></div>';
      set_html('clients-content', html);
    }).catch(function (e) {
      set_html('clients-content', '<p class="err">Error: ' + esc(e.message) + '</p>');
    });
  }

  // ── Clients tab visibility (show only when log_clients on) ─────────────────

  function maybe_show_clients_tab() {
    api('/v0/clients').then(function (d) {
      var tab = document.getElementById('clients-tab');
      if (tab && d.log_clients_enabled) {
        tab.style.display = '';
      }
    }).catch(function () {
      // If the endpoint is missing or errors, keep the tab hidden.
    });
  }

  // ── Tab loader dispatch ─────────────────────────────────────────────────────

  function load_tab(id) {
    switch (id) {
      case 'status':   load_status();   break;
      case 'blocked':  load_blocked();  break;
      case 'insights': load_insights(); break;
      case 'lists':    load_lists();    break;
      case 'privacy':  load_privacy();  break;
      case 'clients':  load_clients();  break;
    }
  }

  // ── Init ────────────────────────────────────────────────────────────────────

  bootstrap_token();
  load_status(); // default active tab
  maybe_show_clients_tab(); // reveal Clients tab if log_clients enabled
})();
