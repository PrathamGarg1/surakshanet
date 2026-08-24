/** Minimal inline flag — no fake Block/Report buttons. */
export function showBanner(el, { severity, maxScore }) {
  if (el.parentElement?.querySelector('.sn-banner')) return;
  el.style.outline = '2px solid #c62828';
  const b = document.createElement('div');
  b.className = 'sn-banner';
  b.textContent = `Abusive (${severity || 'MEDIUM'}) · ${(maxScore * 100).toFixed(0)}%`;
  b.style.cssText =
    'margin-top:4px;padding:6px 8px;font:12px/1.3 system-ui;background:#ffebee;color:#b71c1c;border-left:3px solid #c62828';
  el.parentElement?.appendChild(b);
}
