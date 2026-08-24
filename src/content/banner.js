/** WhatsApp message flag — styled like original UI, no dummy action buttons. */
export function showBanner(el, { severity, maxScore }) {
  const bubble =
    el.closest('.message-in, .message-out, [data-testid="msg-container"]') ||
    el.parentElement?.parentElement ||
    el.parentElement;
  if (!bubble || bubble.querySelector('.suraksha-banner')) return;

  const cfg =
    severity === 'HIGH'
      ? { bg: '#ffebee', border: '#d32f2f', text: '#b71c1c', icon: '🚨', label: 'CRITICAL THREAT' }
      : { bg: '#fff3e0', border: '#f57c00', text: '#e65100', icon: '⚠️', label: 'HARMFUL CONTENT' };

  el.style.border = `2px solid ${cfg.border}`;
  el.style.borderRadius = '6px';
  el.style.backgroundColor = `${cfg.border}12`;

  const banner = document.createElement('div');
  banner.className = 'suraksha-banner';
  banner.style.cssText = `
    background: linear-gradient(135deg, ${cfg.bg} 0%, ${cfg.bg}dd 100%);
    color: ${cfg.text};
    padding: 10px 14px;
    margin-top: 6px;
    border-radius: 6px;
    border-left: 4px solid ${cfg.border};
    font: 12px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    box-shadow: 0 2px 8px rgba(0,0,0,0.12);
  `;
  banner.innerHTML = `
    <div style="display:flex;align-items:center;gap:6px;font-weight:600;">
      <span style="font-size:16px">${cfg.icon}</span>
      <span>${cfg.label} DETECTED</span>
      <span style="background:${cfg.border};color:#fff;padding:2px 6px;border-radius:3px;font-size:10px">${severity || 'MEDIUM'}</span>
    </div>
    <div style="margin-top:4px;font-size:11px;opacity:.9">
      Abusive · ${(maxScore * 100).toFixed(0)}% confidence · logged to evidence chain
    </div>
  `;
  bubble.appendChild(banner);
}
