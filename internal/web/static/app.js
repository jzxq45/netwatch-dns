// monitor UI — progressive enhancement (no framework).
(function () {
  'use strict';

  function escapeHTML(s) {
    if (!s) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function fmtRel(ts) {
    var d = Math.floor(Date.now() / 1000) - ts;
    if (d < 0) d = 0;
    if (d < 5) return 'только что';
    if (d < 60) return d + ' сек назад';
    if (d < 3600) return Math.floor(d / 60) + ' мин назад';
    if (d < 86400) return Math.floor(d / 3600) + ' ч назад';
    return Math.floor(d / 86400) + ' дн назад';
  }

  function fmtClock(ts) {
    var x = new Date(ts * 1000);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return p(x.getHours()) + ':' + p(x.getMinutes()) + ':' + p(x.getSeconds());
  }

  function update() {
    document.querySelectorAll('[data-ts]').forEach(function (el) {
      var ts = parseInt(el.getAttribute('data-ts'), 10);
      if (!ts) return;
      el.title = new Date(ts * 1000).toLocaleString();
      el.textContent = fmtClock(ts) + ' · ' + fmtRel(ts);
    });
  }

  update();
  setInterval(update, 5000);

  // Setup card initialization
  var setupCard = document.getElementById('setupCard');
  if (setupCard) {
    var lanIp = '';
    var localDnsActive = false;
    var autostartActive = false;
    var btnToggle = document.getElementById('btnToggleLocalDns');
    var btnAutostart = document.getElementById('btnToggleAutostart');
    var lblLanIp = document.getElementById('lblLanIp');
    var btnCopy = document.getElementById('btnCopyIp');
    var btnRouter = document.getElementById('btnOpenRouter');
    var errBox = document.getElementById('localDnsError');
    var valBlockedQueries = document.getElementById('valBlockedQueries');
    var valBlockedRules = document.getElementById('valBlockedRules');
    var valCacheRatio = document.getElementById('valCacheRatio');
    var valBlockPct = document.getElementById('valBlockPct');
    var valAIBlocked = document.getElementById('valAIBlocked');
    var servicesCard = document.getElementById('servicesCard');
    var servicesList = document.getElementById('servicesList');
    var btnPhonePair = document.getElementById('btnPhonePair');
    var phonePairCard = document.getElementById('phonePairCard');
    var phonePairAddr = document.getElementById('phonePairAddr');
    var phonePairQR = document.getElementById('phonePairQR');

    function syncPhonePair() {
      if (!lanIp) return;
      var pairUrl = 'http://' + lanIp + (window.location.port ? ':' + window.location.port : '');
      if (phonePairAddr) phonePairAddr.textContent = pairUrl;
      if (phonePairQR) phonePairQR.src = '/api/qr?text=' + encodeURIComponent(pairUrl);
    }

    function applyDnsState(active) {
      localDnsActive = active;
      if (active) {
        btnToggle.textContent = '✓ Активен (отключить)';
        btnToggle.style.borderColor = 'var(--accent2)';
        btnToggle.style.color = 'var(--accent2)';
      } else {
        btnToggle.textContent = 'Включить';
        btnToggle.style.borderColor = 'var(--line)';
        btnToggle.style.color = 'var(--accent)';
      }
    }

    function applyAutostartState(active) {
      autostartActive = active;
      if (!btnAutostart) return;
      if (active) {
        btnAutostart.textContent = '🚀 Автозапуск: вкл';
        btnAutostart.style.borderColor = 'var(--accent2)';
        btnAutostart.style.color = 'var(--accent2)';
      } else {
        btnAutostart.textContent = '🚀 Автозапуск: выкл';
        btnAutostart.style.borderColor = 'var(--line)';
        btnAutostart.style.color = 'var(--text-dim)';
      }
    }

    fetch('/api/network')
      .then(function (r) { return r.json(); })
      .then(function (info) {
        lanIp = info.lan_ip || '127.0.0.1';
        lblLanIp.textContent = 'IP: ' + lanIp;
        if (info.gateway_ip) {
          btnRouter.href = 'http://' + info.gateway_ip;
          btnRouter.title = 'Панель роутера на ' + info.gateway_ip;
        } else {
          btnRouter.style.display = 'none';
        }
        applyDnsState(info.local_dns_enabled);
        applyAutostartState(info.autostart);
        if (valBlockedQueries) valBlockedQueries.textContent = info.blocked_queries || 0;
        if (valBlockedRules) valBlockedRules.textContent = info.blocked_rules || 0;
        if (phonePairAddr) {
          phonePairAddr.textContent = 'http://' + lanIp + (window.location.port ? ':' + window.location.port : '');
        }
        syncPhonePair();
        setupCard.style.display = 'block';
      })
      .catch(function () {});

    // Caps: 24h block percentage and lifetime cache hit ratio from /api/stats.
    fetch('/api/stats')
      .then(function (r) { return r.json(); })
      .then(function (stats) {
        if (valBlockPct) valBlockPct.textContent = Math.round(stats.block_pct || 0);
        if (valCacheRatio) valCacheRatio.textContent = Math.round(stats.cache_hit_ratio || 0);
        if (valAIBlocked) valAIBlocked.textContent = stats.ai_blocked || 0;
      })
      .catch(function () {});

    // 1-click service blocking chips (YouTube, TikTok, ...).
    fetch('/api/services')
      .then(function (r) { return r.json(); })
      .then(function (services) {
        if (!Array.isArray(services) || !services.length || !servicesCard || !servicesList) return;
        servicesCard.style.display = 'block';
        servicesList.innerHTML = '';
        services.forEach(function (svc) {
          var btn = document.createElement('button');
          btn.className = 'chip';
          btn.style.cursor = 'pointer';
          btn.title = svc.domains.join(', ');
          function paint(svc2) {
            if (svc2.blocked) {
              btn.textContent = '🚫 ' + svc2.name;
              btn.style.borderColor = '#ff8080';
              btn.style.color = '#ff8080';
            } else {
              btn.textContent = svc2.name;
              btn.style.borderColor = 'var(--line)';
              btn.style.color = 'var(--text)';
            }
          }
          paint(svc);
          btn.addEventListener('click', function () {
            btn.disabled = true;
            fetch('/api/services/toggle', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ id: svc.id, blocked: !svc.blocked })
            })
            .then(function (r) {
              if (!r.ok) throw new Error('Не удалось изменить блокировку');
              svc.blocked = !svc.blocked;
              paint(svc);
            })
            .catch(function () {})
            .finally(function () { btn.disabled = false; });
          });
          servicesList.appendChild(btn);
          var gap = document.createElement('span');
          gap.textContent = ' ';
          servicesList.appendChild(gap);
        });
      })
      .catch(function () {});

    // Local DNS rewrites: table + quick add/delete.
    var rwCard = document.getElementById('rewritesCard');
    if (rwCard) {
      rwCard.style.display = 'block';
      var rwDomain = document.getElementById('rwDomain');
      var rwIp = document.getElementById('rwIp');
      var btnAddRewrite = document.getElementById('btnAddRewrite');
      var rwError = document.getElementById('rwError');
      var rwTbody = rwCard.querySelector('#rwTable tbody');

      function showRwError(msg) {
        rwError.textContent = msg || '';
        rwError.style.display = msg ? 'inline' : 'none';
      }

      function renderRewrites(list) {
        rwTbody.innerHTML = '';
        if (!Array.isArray(list) || !list.length) {
          var empty = document.createElement('tr');
          empty.innerHTML = '<td class="mute" style="padding:.3rem 0">Записей пока нет — добавьте домен и IP внутренней сети.</td>';
          rwTbody.appendChild(empty);
          return;
        }
        list.forEach(function (rw) {
          var tr = document.createElement('tr');
          var safeDom = escapeHTML(rw.domain);
          var safeIp = escapeHTML(rw.ip);
          tr.innerHTML = '<td style="padding:.25rem 1rem .25rem 0"><span class="chip">' + safeDom + '</span></td>' +
            '<td style="padding:.25rem 1rem .25rem 0"><span class="chip" style="font-family:var(--mono)">' + safeIp + '</span></td>' +
            '<td><button class="chip link btn-rw-del" data-dom="' + safeDom + '" title="Удалить запись" style="cursor:pointer">🗑</button></td>';
          rwTbody.appendChild(tr);
        });
      }

      function loadRewrites() {
        fetch('/api/rewrites')
          .then(function (r) { return r.json(); })
          .then(renderRewrites)
          .catch(function () {});
      }
      loadRewrites();

      btnAddRewrite.addEventListener('click', function () {
        var domain = rwDomain.value.trim();
        var ip = rwIp.value.trim();
        showRwError('');
        if (!domain || !ip) {
          showRwError('Укажите домен и IP');
          return;
        }
        btnAddRewrite.disabled = true;
        fetch('/api/rewrites', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: domain, ip: ip })
        })
        .then(function (r) {
          if (!r.ok) {
            return r.text().then(function (t) { throw new Error(t || 'Ошибка сохранения'); });
          }
          rwDomain.value = '';
          rwIp.value = '';
          loadRewrites();
        })
        .catch(function (e) {
          showRwError(e.message || 'Ошибка сохранения');
        })
        .finally(function () { btnAddRewrite.disabled = false; });
      });

      rwTbody.addEventListener('click', function (ev) {
        var btn = ev.target.closest('.btn-rw-del');
        if (!btn) return;
        var dom = btn.getAttribute('data-dom');
        if (!dom) return;
        btn.disabled = true;
        fetch('/api/rewrites', {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: dom })
        })
        .then(function (r) {
          if (!r.ok) throw new Error('Не удалось удалить');
          loadRewrites();
        })
        .catch(function () {
          btn.disabled = false;
        });
      });
    }

    if (btnPhonePair && phonePairCard) {
      btnPhonePair.addEventListener('click', function () {
        var show = phonePairCard.style.display === 'none' || !phonePairCard.style.display;
        if (show) syncPhonePair();
        phonePairCard.style.display = show ? 'block' : 'none';
      });
      // BUG-09: закрывать подсказку по Escape
      document.addEventListener('keydown', function (ev) {
        if (ev.key === 'Escape' && phonePairCard.style.display !== 'none') {
          phonePairCard.style.display = 'none';
        }
      });
    }

    if (btnCopy) {
      btnCopy.addEventListener('click', function () {
        if (!lanIp) return;
        navigator.clipboard.writeText(lanIp).then(function () {
          var orig = btnCopy.textContent;
          btnCopy.textContent = '✓ Скопировано!';
          setTimeout(function () { btnCopy.textContent = orig; }, 1800);
        });
      });
    }

    if (btnToggle) {
      btnToggle.addEventListener('click', function () {
        // BUG-06: защита от дублирующих кликов
        errBox.style.display = 'none';
        btnToggle.disabled = true;
        btnToggle.textContent = 'Применение...';
        var next = !localDnsActive;
        fetch('/api/local-dns', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: next })
        })
        .then(function (res) {
          if (!res.ok) {
            return res.text().then(function (t) { throw new Error(t); });
          }
          applyDnsState(next);
        })
        .catch(function (err) {
          applyDnsState(localDnsActive);
          errBox.textContent = err.message || 'Ошибка изменения DNS';
          errBox.style.display = 'block';
        })
        .finally(function () { btnToggle.disabled = false; });
      });
    }

    if (btnAutostart) {
      btnAutostart.addEventListener('click', function () {
        // BUG-06: защита от дублирующих кликов
        var next = !autostartActive;
        btnAutostart.disabled = true;
        fetch('/api/autostart', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: next })
        })
        .then(function (res) {
          if (!res.ok) {
            return res.text().then(function (t) { throw new Error(t); });
          }
          applyAutostartState(next);
        })
        .catch(function (err) {
          alert('Ошибка настройки автозапуска: ' + (err.message || err));
        })
        .finally(function () { btnAutostart.disabled = false; });
      });
    }
  }

  // Rename device: inline input instead of window.prompt
  var btnRename = document.getElementById('btnRenameDev');
  var devNameWrap = document.getElementById('devNameWrap');
  if (btnRename && devNameWrap) {
    function staticName() {
      var el = document.getElementById('devNameVal');
      return el ? el.textContent.trim() : '';
    }
    function renderName(name) {
      var shown = name || '\u2014';
      devNameWrap.innerHTML = '<span id="devNameVal"></span> <button class="chip link" id="btnRenameDev" style="cursor:pointer;margin-left:.4rem">\u270F\uFE0F изменить</button>';
      document.getElementById('devNameVal').textContent = shown;
      bindRename();
    }
    function bindRename() {
      var b = document.getElementById('btnRenameDev');
      if (!b) return;
      b.disabled = false;
      b.addEventListener('click', beginRename);
    }
    function beginRename() {
      var curr = staticName();
      if (curr === '\u2014') curr = '';
      var ip = new URLSearchParams(window.location.search).get('ip');
      devNameWrap.innerHTML = '<input type="text" class="chip" id="inputDevName" value="' + escapeHTML(curr) + '"> ' +
        '<button class="chip link" id="btnSaveDevName" style="cursor:pointer">\u2713</button> ' +
        '<button class="chip link" id="btnCancelDevName" style="cursor:pointer">\u2715</button>';
      var input = document.getElementById('inputDevName');
      var btnSave = document.getElementById('btnSaveDevName');
      var btnCancel = document.getElementById('btnCancelDevName');
      input.focus();
      input.select();

      function save() {
        var next = input.value.trim();
        btnSave.disabled = true;
        btnCancel.disabled = true;
        fetch('/api/device/rename', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip, name: next })
        })
        .then(function (r) {
          if (!r.ok) throw new Error('Не удалось сохранить');
          renderName(next);
        })
        .catch(function (e) {
          alert(e.message);
          renderName(staticName() || curr);
        });
      }
      function cancel() { renderName(curr); }

      input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') { ev.preventDefault(); save(); }
        else if (ev.key === 'Escape') { ev.preventDefault(); cancel(); }
      });
      btnSave.addEventListener('click', save);
      btnCancel.addEventListener('click', cancel);
    }
    btnRename.addEventListener('click', beginRename);
    btnRename.disabled = false;
  }

  // Quick block buttons: delegated so static and SSE-inserted rows share it.
  var feedTbody = document.querySelector('table tbody');
  if (feedTbody) {
    feedTbody.addEventListener('click', function (ev) {
      var btn = ev.target.closest('.btn-block-dom');
      if (!btn || btn.disabled) return;
      var dom = btn.getAttribute('data-dom');
      if (!dom) return;
      // BUG-06: защита от дублирующих кликов
      btn.disabled = true;
      fetch('/api/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: dom, action: 'block' })
      })
      .then(function (r) {
        if (!r.ok) throw new Error('Не удалось заблокировать домен');
        btn.textContent = '✓';
        btn.style.borderColor = 'var(--accent2)';
        btn.style.color = 'var(--accent2)';
        btn.disabled = true;
      })
      .catch(function (e) {
        alert(e.message);
        btn.disabled = false;
      });
    });
  }

  // Live SSE stream for real-time feed
  if (feedTbody && window.location.pathname === '/') {
    var source = new EventSource('/api/events/stream');
    source.onmessage = function (ev) {
      if (!ev.data) return;
      try {
        var e = JSON.parse(ev.data);
        var showAll = window.location.search.indexOf('show=all') !== -1;
        if (e.Noise && !showAll) return;

        var tr = document.createElement('tr');
        var d = new Date(e.TS * 1000);
        function pad(n) { return (n < 10 ? '0' : '') + n; }
        var timeStr = pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());

        var noiseBadge = e.Noise ? ' <span class="badge blocked">noise</span>' : '';
        var safeClient = escapeHTML(e.ClientIP);
        var safeKind = escapeHTML(e.Kind);
        var safeName = escapeHTML(e.Name);

        tr.innerHTML = '<td class="time" data-ts="' + Number(e.TS) + '">' + timeStr + ' · только что</td>' +
          '<td><span class="badge ' + safeKind + '">' + safeKind + '</span></td>' +
          '<td><a class="chip link" href="/device?ip=' + encodeURIComponent(e.ClientIP) + '">' + safeClient + '</a></td>' +
          '<td class="dom">' + safeName + noiseBadge +
          '<button class="chip btn-block-dom" data-dom="' + safeName + '" title="Заблокировать этот домен" style="cursor:pointer;padding:0 .35rem;margin-left:.35rem;font-size:.7rem">🚫</button></td>';

        feedTbody.insertBefore(tr, feedTbody.firstChild);
        while (feedTbody.children.length > 100) {
          feedTbody.removeChild(feedTbody.lastChild);
        }
      } catch (err) {}
    };
  }
})();
