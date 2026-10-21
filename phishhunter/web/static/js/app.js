(() => {
  const root = document.documentElement;
  const body = document.body;
  const accountToggle = document.querySelector('[data-account-toggle]');
  const accountMenu = document.querySelector('[data-account-menu]');
  const accountWrap = document.querySelector('[data-account-wrap]');
  const mobile = document.querySelector('[data-mobile-menu]');
  const mobileButton = document.querySelector('[data-mobile-button]');
  // K4 uses a single, consistent dark analyst theme. Theme switching is intentionally disabled.
  body.dataset.theme = 'blacklight';

  const closeAccount = () => {
    if (!accountMenu || !accountToggle) return;
    accountMenu.classList.remove('open');
    accountMenu.setAttribute('aria-hidden', 'true');
    accountToggle.setAttribute('aria-expanded', 'false');
  };
  if (accountToggle && accountMenu) {
    accountToggle.addEventListener('click', (event) => {
      event.stopPropagation();
      const open = accountMenu.classList.toggle('open');
      accountMenu.setAttribute('aria-hidden', String(!open));
      accountToggle.setAttribute('aria-expanded', String(open));
    });
    document.addEventListener('click', (event) => {
      if (accountWrap && !accountWrap.contains(event.target)) closeAccount();
    });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closeAccount(); });
  }

  if (mobile && mobileButton) {
    mobileButton.addEventListener('click', () => {
      mobile.classList.toggle('hidden');
      mobileButton.setAttribute('aria-expanded', String(!mobile.classList.contains('hidden')));
    });
  }

  let raf = 0;
  window.addEventListener('pointermove', (event) => {
    if (raf) cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => {
      root.style.setProperty('--k4-mx', `${event.clientX}px`);
      root.style.setProperty('--k4-my', `${event.clientY}px`);
    });
  }, { passive: true });

  document.querySelectorAll('[data-copy]').forEach((el) => {
    el.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(el.dataset.copy);
        const old = el.textContent; el.textContent = 'Copied';
        setTimeout(() => { el.textContent = old || 'Copy'; }, 1200);
      } catch (_) {}
    });
  });

  document.querySelectorAll('form[data-progress-form]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (form.dataset.progressBound === '1') return;
      event.preventDefault(); form.dataset.progressBound = '1';
      const panel = form.closest('section')?.querySelector('[data-progress-panel]') || document.querySelector('[data-progress-panel]');
      if (!panel) { form.submit(); return; }
      panel.classList.remove('hidden');
      const bar = panel.querySelector('[data-progress-bar]');
      const percent = panel.querySelector('[data-progress-percent]');
      const stage = panel.querySelector('[data-progress-stage]');
      const steps = [...panel.querySelectorAll('[data-progress-step]')];
      const setProgress = (n, labelText) => {
        if (bar) bar.style.width = `${Math.max(0, Math.min(100, n))}%`;
        if (percent) percent.textContent = `${Math.round(n)}%`;
        if (stage) stage.textContent = labelText;
        const active = n >= 90 ? 4 : n >= 65 ? 3 : n >= 35 ? 2 : 1;
        steps.forEach((x, i) => x.classList.toggle('k4-progress-active', i < active));
      };
      setProgress(8, 'Validating evidence…');
      const xhr = new XMLHttpRequest(); xhr.open(form.method || 'POST', form.action || location.href, true); xhr.responseType = 'text';
      xhr.upload.addEventListener('progress', (e) => { if (e.lengthComputable) setProgress(Math.min(34, 8 + (e.loaded / e.total) * 26), 'Uploading evidence…'); });
      let simulated = 34;
      const timer = setInterval(() => { if (simulated < 92) { simulated += simulated < 65 ? 4 : 1.5; setProgress(simulated, simulated < 65 ? 'Running deep analysis…' : simulated < 82 ? 'Correlating evidence and IOCs…' : 'Building analyst report…'); } }, 450);
      xhr.onload = () => { clearInterval(timer); setProgress(100, 'Analysis complete. Loading result…'); if (xhr.status >= 200 && xhr.status < 400 && xhr.responseText) { document.open(); document.write(xhr.responseText); document.close(); } else { setProgress(100, `Analysis returned HTTP ${xhr.status}`); form.dataset.progressBound = '0'; } };
      xhr.onerror = () => { clearInterval(timer); setProgress(100, 'Connection error.'); form.dataset.progressBound = '0'; };
      xhr.send(new FormData(form));
    });
  });
})();
