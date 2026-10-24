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
  // 진행 중 작업이 있으면 자동 새로고침: <meta name="ps-refresh" content="5">
  var m = document.querySelector('meta[name=ps-refresh]');
  if (m) setTimeout(function () { location.reload(); }, parseInt(m.content, 10) * 1000);
})();
