// monitor UI — small progressive enhancement (no framework).
// Turns data-ts attributes into "HH:MM:SS · N мин назад" and refreshes
// relative times in place.
(function () {
  'use strict';

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
})();
