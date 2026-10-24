// 최소 상호작용 (CSP 'self'). 모든 기능은 JS 없이도 동작하고, JS 는 편의만 더한다.
(function () {
  // 표 필터: <input data-filter="#tableId">
  document.querySelectorAll('input[data-filter]').forEach(function (inp) {
    var table = document.querySelector(inp.getAttribute('data-filter'));
    if (!table) return;
    var count = document.querySelector(inp.getAttribute('data-count') || '#none');
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase(), n = 0;
      table.querySelectorAll('tbody tr').forEach(function (tr) {
        var show = !q || tr.textContent.toLowerCase().indexOf(q) >= 0;
        tr.hidden = !show; if (show) n++;
      });
      if (count) count.textContent = n;
    });
  });
  // 체크박스 선택 수 표시 + 제출 버튼 활성화: <form data-select-count="#n" data-submit="#btn">
  document.querySelectorAll('form[data-select-count]').forEach(function (f) {
    var out = document.querySelector(f.getAttribute('data-select-count'));
    var btn = document.querySelector(f.getAttribute('data-submit'));
    function upd() {
      var mode = f.querySelector('input[name=mode]:checked');
      var n = f.querySelectorAll('input[name=packages]:checked').length;
      if (out) out.textContent = n;
      if (btn) btn.disabled = mode && mode.value === 'selected' && n === 0;
    }
    f.addEventListener('change', upd); upd();
    var all = f.querySelector('[data-check-visible]');
    if (all) all.addEventListener('click', function (e) {
      e.preventDefault();
      f.querySelectorAll('tbody tr:not([hidden]) input[name=packages]').forEach(function (c) { c.checked = true; });
      var sel = f.querySelector('input[name=mode][value=selected]'); if (sel) sel.checked = true;
      upd();
    });
  });
  // 카드(details) 필터: <input data-filter-cards="#container">  — 일치하면 펼침
  document.querySelectorAll('input[data-filter-cards]').forEach(function (inp) {
    var box = document.querySelector(inp.getAttribute('data-filter-cards'));
    if (!box) return;
    inp.addEventListener('input', function () {
      var q = inp.value.trim().toLowerCase();
      box.querySelectorAll(':scope > details').forEach(function (d) {
        var hit = !q || d.textContent.toLowerCase().indexOf(q) >= 0;
        d.hidden = !hit;
        if (q && hit) d.open = true;
      });
    });
  });
  // 모두 펼치기/접기: <button data-toggle-all="#container">
  document.querySelectorAll('[data-toggle-all]').forEach(function (btn) {
    var box = document.querySelector(btn.getAttribute('data-toggle-all'));
    if (!box) return;
    btn.addEventListener('click', function () {
      var ds = box.querySelectorAll(':scope > details:not([hidden])');
      var anyClosed = Array.prototype.some.call(ds, function (d) { return !d.open; });
      ds.forEach(function (d) { d.open = anyClosed; });
    });
  });
  // 의존 트리: <details data-deps-url> 를 펼칠 때 한 단계씩 불러온다 (중첩 포함, 이벤트 위임)
  document.addEventListener('toggle', function (e) {
    var d = e.target;
    if (!d.matches || !d.matches('details[data-deps-url]') || !d.open || d.dataset.loaded) return;
    d.dataset.loaded = '1';
    var body = d.querySelector(':scope > .deps-body');
    fetch(d.getAttribute('data-deps-url'), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
      .then(function (html) { body.innerHTML = html; })
      .catch(function (err) { body.textContent = '불러오지 못했습니다 (' + err.message + '). 다시 펼쳐 보세요.'; delete d.dataset.loaded; });
  }, true);
  // 진행 중 작업이 있으면 자동 새로고침: <meta name="ps-refresh" content="5">
  var m = document.querySelector('meta[name=ps-refresh]');
  if (m) setTimeout(function () { location.reload(); }, parseInt(m.content, 10) * 1000);
})();
