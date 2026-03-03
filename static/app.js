// Shared utility: copy output to clipboard
function copyOutput(id) {
  const el = document.getElementById(id);
  const text = el.innerText;
  navigator.clipboard.writeText(text).then(() => {
    const btn = el.closest('.output-panel')?.querySelector('.copy-btn');
    if (btn) {
      btn.classList.add('copy-success');
      setTimeout(() => btn.classList.remove('copy-success'), 1200);
    }
  });
}

function animateSwap(el) {
  if (!el) return;
  el.classList.remove('content-swap');
  // Force reflow to restart animation on subsequent updates.
  void el.offsetWidth;
  el.classList.add('content-swap');
}

document.addEventListener('DOMContentLoaded', () => {
  const motionSelectors = [
    '.hero-banner',
    '.tool-card',
    '.recent-section',
    '.tool-header',
    '.panel',
    '.diag-box',
    '.output-content',
    '.btn-primary',
    '.btn-execute'
  ];

  const motionItems = [...document.querySelectorAll(motionSelectors.join(','))];
  motionItems.forEach((el, i) => {
    el.classList.add('motion-item');
    el.style.transitionDelay = `${Math.min(i * 50, 450)}ms`;
  });

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );

  motionItems.forEach((el) => observer.observe(el));
});