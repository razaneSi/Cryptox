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

  const settingsModal = document.getElementById('settings-modal');
  const profileTrigger = document.getElementById('profile-trigger');
  const closeSettingsEls = document.querySelectorAll('[data-close-settings]');
  const settingsFeedback = document.getElementById('settings-feedback');
  const usernameForm = document.getElementById('username-form');
  const passwordForm = document.getElementById('password-form');
  const deleteForm = document.getElementById('delete-account-form');

  const showFeedback = (message, kind) => {
    if (!settingsFeedback) return;
    settingsFeedback.textContent = message;
    settingsFeedback.className = `settings-feedback is-visible ${kind}`;
  };

  const openSettings = () => {
    if (!settingsModal) return;
    settingsModal.hidden = false;
  };

  const closeSettings = () => {
    if (!settingsModal) return;
    settingsModal.hidden = true;
  };

  profileTrigger?.addEventListener('click', openSettings);
  closeSettingsEls.forEach((el) => el.addEventListener('click', closeSettings));

  usernameForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = document.getElementById('settings-username').value.trim();
    const currentPassword = document.getElementById('settings-username-password').value;
    const response = await fetch('/api/account/update-username', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, current_password: currentPassword })
    });
    const data = await response.json();
    if (!response.ok) {
      showFeedback(data.error || 'Unable to update username.', 'error');
      return;
    }

    const currentBadge = document.getElementById('profile-trigger');
    if (currentBadge) {
      currentBadge.textContent = data.username[0].toUpperCase();
    }
    const oldUsername = document.body.dataset.username || '';
    const oldKeys = localStorage.getItem(`cryptox.keys.${oldUsername}`);
    if (oldKeys) {
      localStorage.setItem(`cryptox.keys.${data.username}`, oldKeys);
      localStorage.removeItem(`cryptox.keys.${oldUsername}`);
    }
    showFeedback(data.message, 'success');
    window.setTimeout(() => window.location.reload(), 700);
  });

  passwordForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const currentPassword = document.getElementById('settings-current-password').value;
    const newPassword = document.getElementById('settings-new-password').value;
    const confirmPassword = document.getElementById('settings-confirm-password').value;
    const response = await fetch('/api/account/update-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword
      })
    });
    const data = await response.json();
    showFeedback(response.ok ? data.message : (data.error || 'Unable to update password.'), response.ok ? 'success' : 'error');
    if (response.ok) {
      passwordForm.reset();
    }
  });

  deleteForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!window.confirm('Delete your account permanently?')) {
      return;
    }
    const currentPassword = document.getElementById('settings-delete-password').value;
    const response = await fetch('/api/account/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ current_password: currentPassword })
    });
    const data = await response.json();
    if (!response.ok) {
      showFeedback(data.error || 'Unable to delete account.', 'error');
      return;
    }
    window.location.href = '/login';
  });
});