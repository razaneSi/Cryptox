const messengerShell = document.querySelector(".messenger-shell");

if (messengerShell) {
  const state = {
    currentUser: messengerShell.dataset.username,
    users: [],
    conversations: [],
    currentConversation: null,
    conversationRenderCache: {},
    conversationLoadSeq: 0,
    socket: null,
    joinedConversationId: null,
    refreshInFlight: null,
    addMemberChoice: null,
    localKeys: null,
    publicKeyCache: {},
    poller: null,
    pendingAttachment: null,
    mediaRecorder: null,
    mediaChunks: [],
    mediaStream: null,
    decryptedCache: {},
  };

  const els = {
    contactList: document.getElementById("contact-list"),
    groupForm: document.getElementById("group-form"),
    groupName: document.getElementById("group-name"),
    statusText: document.getElementById("messenger-status-text"),
    conversationTitle: document.getElementById("conversation-title"),
    messageThread: document.getElementById("message-thread"),
    metaText: document.getElementById("message-meta-text"),
    composeForm: document.getElementById("compose-form"),
    messageInput: document.getElementById("message-input"),
    sendBtn: document.getElementById("send-btn"),
    refreshUsersBtn: document.getElementById("refresh-users-btn"),
    addMemberWrap: document.getElementById("add-member-wrap"),
    addMemberToggle: document.getElementById("add-member-toggle"),
    addMemberPopover: document.getElementById("add-member-popover"),
    addMemberPicker: document.getElementById("add-member-picker"),
    addMemberPickerBtn: document.getElementById("add-member-picker-btn"),
    addMemberPickerLabel: document.getElementById("add-member-picker-label"),
    addMemberOptions: document.getElementById("add-member-options"),
    addMemberBtn: document.getElementById("add-member-btn"),
    fileInput: document.getElementById("file-input"),
    attachBtn: document.getElementById("attach-btn"),
    recordBtn: document.getElementById("record-btn"),
    clearAttachmentBtn: document.getElementById("clear-attachment-btn"),
  };

  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  const keyStorageKey = (username) => `cryptox.keys.${username}`;

  const escapeHtml = (value) =>
    String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char]));

  const setStatus = (message) => {
    els.statusText.textContent = message;
  };

  const setMeta = (message) => {
    els.metaText.textContent = message;
  };

  const api = async (url, options = {}) => {
    const response = await fetch(url, {
      headers: { "Content-Type": "application/json", ...(options.headers || {}) },
      ...options,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || "Request failed.");
    }
    return data;
  };

  const arrayBufferToBase64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    bytes.forEach((byte) => {
      binary += String.fromCharCode(byte);
    });
    return btoa(binary);
  };

  const base64ToArrayBuffer = (base64) => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  };

  const mergeUint8Arrays = (...arrays) => {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const merged = new Uint8Array(totalLength);
    let offset = 0;
    arrays.forEach((arr) => {
      merged.set(arr, offset);
      offset += arr.length;
    });
    return merged;
  };

  const formatTimestamp = (value) => {
    const date = new Date(value.replace(" ", "T") + "Z");
    if (Number.isNaN(date.getTime())) return value;

    const now = new Date();
    const diff = now - date;
    const isToday = diff < 24 * 60 * 60 * 1000 && now.getDate() === date.getDate();

    const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    if (isToday) return timeStr;

    const dateStr = date.toLocaleDateString([], { month: "short", day: "numeric" });
    return `${dateStr}, ${timeStr}`;
  };

  const bytesToHex = (buffer) =>
    [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

  const computeSha256 = async (buffer) => bytesToHex(await crypto.subtle.digest("SHA-256", buffer));

  const exportSpkiBase64 = async (key) => arrayBufferToBase64(await crypto.subtle.exportKey("spki", key));
  const exportJwk = async (key) => crypto.subtle.exportKey("jwk", key);

  const importEncryptionPublicKey = (base64) =>
    crypto.subtle.importKey("spki", base64ToArrayBuffer(base64), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);

  const importSigningPublicKey = (base64) =>
    crypto.subtle.importKey("spki", base64ToArrayBuffer(base64), { name: "RSA-PSS", hash: "SHA-256" }, true, ["verify"]);

  const importStoredPrivateKeys = async (stored) => {
    const decryptPrivateKey = await crypto.subtle.importKey(
      "jwk",
      stored.decryptPrivateJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
    const signingPrivateKey = await crypto.subtle.importKey(
      "jwk",
      stored.signPrivateJwk,
      { name: "RSA-PSS", hash: "SHA-256" },
      true,
      ["sign"]
    );
    return {
      publicEncryptionKey: stored.publicEncryptionKey,
      publicSigningKey: stored.publicSigningKey,
      decryptPrivateKey,
      signingPrivateKey,
    };
  };

  const generateAndStoreLocalKeys = async () => {
    setStatus("Generating device RSA key pairs...");
    const encryptionKeys = await crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    const signingKeys = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

    const stored = {
      publicEncryptionKey: await exportSpkiBase64(encryptionKeys.publicKey),
      publicSigningKey: await exportSpkiBase64(signingKeys.publicKey),
      decryptPrivateJwk: await exportJwk(encryptionKeys.privateKey),
      signPrivateJwk: await exportJwk(signingKeys.privateKey),
    };
    localStorage.setItem(keyStorageKey(state.currentUser), JSON.stringify(stored));
    return importStoredPrivateKeys(stored);
  };

  const ensureLocalKeys = async () => {
    const stored = localStorage.getItem(keyStorageKey(state.currentUser));
    if (stored) {
      return importStoredPrivateKeys(JSON.parse(stored));
    }
    return generateAndStoreLocalKeys();
  };

  const registerPublicKeys = async () => {
    const data = await api("/api/messenger/register-key", {
      method: "POST",
      body: JSON.stringify({
        public_encryption_key: state.localKeys.publicEncryptionKey,
        public_signing_key: state.localKeys.publicSigningKey,
      }),
    });
    setStatus("Device keys registered and signed by CryptoX CA (X.509).");
    return data;
  };

  const fetchUsers = async () => {
    const data = await api("/api/messenger/users");
    state.users = data.users;
    renderContacts();
    renderAddMemberOptions();
  };

  const fetchConversations = async () => {
    const data = await api("/api/messenger/conversations");
    state.conversations = data.conversations;
    renderContacts();
  };

  const getConversationById = (conversationId) =>
    state.conversations.find((conversation) => Number(conversation.id) === Number(conversationId));

  const renderContacts = () => {
    const groups = state.conversations.filter((conversation) => conversation.is_group);
    if (!state.users.length && !groups.length) {
      els.contactList.innerHTML = '<div class="messenger-empty-state">Create another account or group to start a chat.</div>';
      return;
    }

    const directItems = state.users.map((user) => {
        const active =
          state.currentConversation &&
          !state.currentConversation.is_group &&
          state.currentConversation.members.includes(user.username);
        const initials = user.username.slice(0, 2).toUpperCase();
        const isBlockedByYou = Boolean(user.blocked_by_you);
        return `
          <div class="messenger-contact-card-wrap" data-card-wrap>
            <button class="messenger-contact-card ${active ? "active" : ""}" data-direct-user="${escapeHtml(user.username)}" type="button" title="${escapeHtml(user.username)}">
              <div class="messenger-contact-avatar">${escapeHtml(initials)}</div>
              <div class="messenger-contact-meta">
                <span class="messenger-contact-name">${escapeHtml(user.username)}</span>
                <span class="messenger-contact-ready ${isBlockedByYou ? "waiting" : (user.ready ? "ready" : "waiting")}">${isBlockedByYou ? "Blocked" : (user.ready ? "Ready" : "No keys")}</span>
              </div>
            </button>
            <button class="messenger-contact-menu-btn" data-contact-menu-toggle type="button" title="Chat actions" aria-label="Chat actions">...</button>
            <div class="messenger-contact-menu" data-contact-menu hidden>
              ${
                isBlockedByYou
                  ? `<button type="button" data-action-unblock="${escapeHtml(user.username)}">
                       <span class="menu-icon">&#9989;</span>
                       <span>Unblock</span>
                     </button>`
                  : `<button type="button" data-action-block="${escapeHtml(user.username)}">
                       <span class="menu-icon">&#128683;</span>
                       <span>Block</span>
                     </button>`
              }
            </div>
          </div>
        `;
      });

    const groupItems = groups.map((conversation) => {
      const active = state.currentConversation?.id === conversation.id;
      const initials = conversation.name
        .split(" ")
        .map((part) => part[0])
        .join("")
        .slice(0, 2)
        .toUpperCase();
      return `
        <div class="messenger-contact-card-wrap" data-card-wrap>
          <button class="messenger-contact-card messenger-contact-card-group ${active ? "active" : ""}" data-conversation-id="${conversation.id}" type="button" title="${escapeHtml(conversation.name)}">
            <div class="messenger-contact-avatar messenger-contact-avatar-group">${escapeHtml(initials)}</div>
            <div class="messenger-contact-meta">
              <span class="messenger-contact-name">${escapeHtml(conversation.name)}</span>
              <span class="messenger-contact-ready ready">Group</span>
            </div>
          </button>
          <button class="messenger-contact-menu-btn" data-contact-menu-toggle type="button" title="Group actions" aria-label="Group actions">...</button>
          <div class="messenger-contact-menu" data-contact-menu hidden>
            <button type="button" data-action-leave-group="${conversation.id}">
              <span class="menu-icon">&#8617;</span>
              <span>Leave Group</span>
            </button>
          </div>
        </div>
      `;
    });

    els.contactList.innerHTML = [...directItems, ...groupItems].join("");

    els.contactList.querySelectorAll("[data-direct-user]").forEach((button) => {
      button.addEventListener("click", () => openDirectConversation(button.dataset.directUser));
    });

    els.contactList.querySelectorAll("[data-conversation-id]").forEach((button) => {
      button.addEventListener("click", () => selectConversation(Number(button.dataset.conversationId)));
    });

    els.contactList.querySelectorAll("[data-contact-menu-toggle]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        const wrap = button.closest("[data-card-wrap]");
        const menu = wrap?.querySelector("[data-contact-menu]");
        const currentlyOpen = !menu?.hidden;
        closeAllContactMenus();
        if (menu && !currentlyOpen) {
          menu.hidden = false;
        }
      });
    });

    els.contactList.querySelectorAll("[data-action-block]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const username = button.dataset.actionBlock;
        await api("/api/messenger/block", {
          method: "POST",
          body: JSON.stringify({ username }),
        });
        closeAllContactMenus();
        await refreshData();
        setMeta(`${username} is now blocked. Direct sending is disabled until you unblock.`);
      });
    });

    els.contactList.querySelectorAll("[data-action-unblock]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const username = button.dataset.actionUnblock;
        await api("/api/messenger/unblock", {
          method: "POST",
          body: JSON.stringify({ username }),
        });
        closeAllContactMenus();
        await refreshData();
        setMeta(`${username} is now unblocked.`);
      });
    });

    els.contactList.querySelectorAll("[data-action-leave-group]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const conversationId = Number(button.dataset.actionLeaveGroup);
        await api(`/api/messenger/conversations/${conversationId}/leave`, {
          method: "POST",
        });
        closeAllContactMenus();
        if (state.currentConversation?.id === conversationId) {
          state.currentConversation = null;
          els.conversationTitle.textContent = "Choose a chat";
          els.messageInput.disabled = true;
          els.sendBtn.disabled = true;
          els.recordBtn.disabled = true;
          renderEmptyThread("Group left", "You left this group conversation.");
        }
        await refreshData();
        setMeta("You left the group.");
      });
    });
  };

  const closeAllContactMenus = () => {
    els.contactList.querySelectorAll("[data-contact-menu]").forEach((menu) => {
      menu.hidden = true;
    });
  };

  const closeAllMessageMenus = () => {
    if (!els.messageThread) return;
    els.messageThread.querySelectorAll("[data-message-menu]").forEach((menu) => {
      menu.hidden = true;
    });
  };

  const ensureSocket = () => {
    if (state.socket || typeof window.io !== "function") return;
    const socket = window.io();
    state.socket = socket;

    socket.on("messenger:connected", () => {
      if (state.currentConversation?.id) {
        socket.emit("messenger:join_conversation", { conversation_id: state.currentConversation.id });
        state.joinedConversationId = state.currentConversation.id;
      }
    });

    socket.on("messenger:refresh", () => {
      refreshData().catch((error) => setMeta(error.message));
    });

    socket.on("messenger:conversation_refresh", (payload) => {
      const conversationId = Number(payload?.conversation_id);
      if (!conversationId) return;
      if (state.currentConversation?.id === conversationId) {
        loadConversation(conversationId).catch((error) => setMeta(error.message));
      } else {
        fetchConversations().catch((error) => setMeta(error.message));
      }
    });

    socket.on("messenger:member_added", (payload) => {
      const conversationId = Number(payload?.conversation_id);
      if (!conversationId) return;
      if (state.currentConversation?.id === conversationId) {
        loadConversation(conversationId).catch((error) => setMeta(error.message));
      } else {
        fetchConversations().catch((error) => setMeta(error.message));
      }
    });
  };

  const closeAddMemberOptions = () => {
    if (els.addMemberOptions) {
      els.addMemberOptions.hidden = true;
    }
  };

  const renderAddMemberOptions = () => {
    // Always keep the add panel collapsed until the user explicitly clicks "+".
    els.addMemberPopover.hidden = true;
    closeAddMemberOptions();
    if (!state.currentConversation || !state.currentConversation.is_group) {
      els.addMemberWrap.hidden = true;
      state.addMemberChoice = null;
      return;
    }
    els.addMemberWrap.hidden = false;
    const availableUsers = state.users.filter((user) => !state.currentConversation.members.includes(user.username) && user.ready);
    if (!availableUsers.length) {
      state.addMemberChoice = null;
      els.addMemberPickerLabel.textContent = "No users available";
      els.addMemberPickerBtn.disabled = true;
      els.addMemberBtn.disabled = true;
      els.addMemberOptions.innerHTML = `
        <div class="messenger-member-option is-disabled">
          <span class="messenger-member-option-check"></span>
          <span>No eligible users</span>
        </div>
      `;
      return;
    }
    els.addMemberPickerBtn.disabled = false;
    els.addMemberBtn.disabled = false;
    const selected = state.addMemberChoice && availableUsers.some((user) => user.username === state.addMemberChoice)
      ? state.addMemberChoice
      : availableUsers[0].username;
    state.addMemberChoice = selected;
    els.addMemberPickerLabel.textContent = selected;
    els.addMemberOptions.innerHTML = availableUsers
      .map((user) => `
        <button
          type="button"
          class="messenger-member-option ${user.username === selected ? "selected" : ""}"
          data-add-member-username="${escapeHtml(user.username)}"
        >
          <span class="messenger-member-option-check">${user.username === selected ? "✓" : ""}</span>
          <span>${escapeHtml(user.username)}</span>
        </button>
      `)
      .join("");

    els.addMemberOptions.querySelectorAll("[data-add-member-username]").forEach((button) => {
      button.addEventListener("click", () => {
        state.addMemberChoice = button.dataset.addMemberUsername;
        els.addMemberPickerLabel.textContent = state.addMemberChoice;
        els.addMemberOptions.querySelectorAll(".messenger-member-option").forEach((optionButton) => {
          const isSelected = optionButton.dataset.addMemberUsername === state.addMemberChoice;
          optionButton.classList.toggle("selected", isSelected);
          const check = optionButton.querySelector(".messenger-member-option-check");
          if (check) check.textContent = isSelected ? "✓" : "";
        });
        closeAddMemberOptions();
      });
    });
  };

  const renderEmptyThread = (title, subtitle) => {
    els.messageThread.innerHTML = `
      <div class="messenger-thread-empty">
        <h4>${escapeHtml(title)}</h4>
        <p>${escapeHtml(subtitle)}</p>
      </div>
    `;
  };

  const ensurePublicKeys = async (username) => {
    if (!state.publicKeyCache[username]) {
      const keyData = await api(`/api/messenger/get-key/${encodeURIComponent(username)}`);
      if (!keyData.encryption_certificate_valid || !keyData.signing_certificate_valid) {
        throw new Error(`CA certificate verification failed for ${username}.`);
      }
      state.publicKeyCache[username] = {
        encryptionKey: await importEncryptionPublicKey(keyData.public_encryption_key),
        signingKey: await importSigningPublicKey(keyData.public_signing_key),
      };
    }
    return state.publicKeyCache[username];
  };

  const base64ToBlobUrl = (base64, mimeType) => {
    const bytes = new Uint8Array(base64ToArrayBuffer(base64));
    return URL.createObjectURL(new Blob([bytes], { type: mimeType }));
  };

  const decryptMessage = async (message) => {
    const senderKeys = await ensurePublicKeys(message.sender);
    const encryptedBytes = new Uint8Array(base64ToArrayBuffer(message.encrypted_payload));
    const tagBytes = new Uint8Array(base64ToArrayBuffer(message.tag));
    const merged = mergeUint8Arrays(encryptedBytes, tagBytes);

    const verified = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      senderKeys.signingKey,
      base64ToArrayBuffer(message.signature),
      encryptedBytes
    );

    const rawAesKey = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      state.localKeys.decryptPrivateKey,
      base64ToArrayBuffer(message.encrypted_aes_key)
    );
    const aesKey = await crypto.subtle.importKey("raw", rawAesKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const plaintextBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToArrayBuffer(message.nonce) },
      aesKey,
      merged
    );
    const payload = JSON.parse(textDecoder.decode(plaintextBuffer));

    let hashValid = true;
    let objectUrl = null;
    if (payload.data_base64 && payload.hash) {
      const bytes = base64ToArrayBuffer(payload.data_base64);
      hashValid = (await computeSha256(bytes)) === payload.hash;
      objectUrl = base64ToBlobUrl(payload.data_base64, payload.mime_type);
    }

    return { payload, verified, hashValid, objectUrl };
  };

  const renderPayload = (result) => {
    const textBlock = result.payload.text ? `<div class="messenger-message-text">${escapeHtml(result.payload.text)}</div>` : "";
    if (result.payload.kind === "voice") {
      const waveform = Array.from({ length: 28 }, (_, index) => {
        const height = 6 + ((index * 7) % 24);
        return `<span style="height:${height}px"></span>`;
      }).join("");
      return `
        <div class="messenger-voice-row">
          <button class="messenger-voice-play" type="button" data-audio-toggle="${escapeHtml(result.objectUrl)}">▶</button>
          <div class="messenger-waveform">${waveform}</div>
          <div class="messenger-voice-time">${result.payload.duration || "0:52"}</div>
        </div>
        ${textBlock}
        <audio src="${result.objectUrl}" data-audio-source="${escapeHtml(result.objectUrl)}" hidden></audio>
      `;
    }
    if (result.payload.kind === "file") {
      const fileSize = result.payload.size
        ? (result.payload.size < 1024 ? `${result.payload.size} B` : `${Math.ceil(result.payload.size / 1024)} KB`)
        : "file";
        
      let mediaPreview = "";
      if (result.payload.mime_type && result.payload.mime_type.startsWith("image/")) {
        mediaPreview = `<img src="${result.objectUrl}" alt="${escapeHtml(result.payload.file_name)}" class="messenger-media-preview" style="max-width: 100%; border-radius: 8px; margin-bottom: 8px; object-fit: contain;" />`;
      } else if (result.payload.mime_type && result.payload.mime_type.startsWith("video/")) {
        mediaPreview = `<video src="${result.objectUrl}" controls class="messenger-media-preview" style="max-width: 100%; border-radius: 8px; margin-bottom: 8px;"></video>`;
      }

      return `
        ${mediaPreview}
        ${textBlock}
        <a class="messenger-file-chip" href="${result.objectUrl}" download="${escapeHtml(result.payload.file_name)}">
          <div class="messenger-file-icon">📄</div>
          <div class="messenger-file-text">
            <strong>${escapeHtml(result.payload.file_name)}</strong>
            <span>${escapeHtml(fileSize)}</span>
          </div>
        </a>
      `;
    }
    return `<div class="messenger-message-text">${escapeHtml(result.payload.text || "")}</div>`;
  };

  const renderMessages = async (messages, options = {}) => {
    const { forceScrollBottom = false, preDecrypted = false } = options;
    const previousScrollTop = els.messageThread.scrollTop;
    const previousScrollHeight = els.messageThread.scrollHeight;
    const wasNearBottom =
      previousScrollHeight - (previousScrollTop + els.messageThread.clientHeight) < 56;

    if (!messages.length) {
      renderEmptyThread("No messages yet", "Send the first encrypted message, voice note, or file to start this chat.");
      return;
    }

    const decrypted = preDecrypted
      ? messages
      : await Promise.all(
          messages.map(async (message) => {
            if (state.decryptedCache[message.id]) {
              return state.decryptedCache[message.id];
            }
            try {
              const result = { ...message, ...await decryptMessage(message) };
              state.decryptedCache[message.id] = result;
              return result;
            } catch (_error) {
              const fallback = {
                ...message,
                payload: { kind: "text", text: "Unable to decrypt this message on this device." },
                verified: false,
                hashValid: false,
                objectUrl: null,
              };
              // We don't necessarily cache failures as they might be transient (e.g. key loading)
              return fallback;
            }
          })
        );

    els.messageThread.innerHTML = decrypted
      .map((message) => {
        const outgoing = message.sender === state.currentUser;
        const integrityParts = [message.verified ? "signature verified" : "signature failed"];
        if (message.payload.kind === "file" || message.payload.kind === "voice") {
          integrityParts.push(message.hashValid ? "SHA-256 file hash verified" : "SHA-256 file hash failed");
        }
        return `
          <div class="messenger-bubble-row ${outgoing ? "outgoing" : "incoming"}">
            <article class="messenger-bubble ${outgoing ? "outgoing" : "incoming"}">
              <span class="messenger-message-sender">${escapeHtml(outgoing ? "You" : message.sender)}</span>
              ${renderPayload(message)}
              <div class="messenger-message-meta">${formatTimestamp(message.created_at)} · ${integrityParts.join(" · ")}</div>
              ${outgoing ? `
                <div class="messenger-bubble-menu-wrap">
                  <button type="button" class="messenger-bubble-menu-trigger" data-message-menu-trigger="${message.id}" title="Message actions">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                      <circle cx="12" cy="5" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="12" cy="19" r="1.2"/>
                    </svg>
                  </button>
                  <div class="messenger-bubble-menu" data-message-menu="${message.id}" hidden>
                    <button type="button" class="messenger-bubble-menu-action" data-action-delete-message="${message.id}">
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              ` : ''}
            </article>
          </div>
        `;
      })
      .join("");

    els.messageThread.querySelectorAll("[data-message-menu-trigger]").forEach((button) => {
      button.addEventListener("click", (event) => {
        event.stopPropagation();
        const id = button.dataset.messageMenuTrigger;
        const menu = els.messageThread.querySelector(`[data-message-menu="${CSS.escape(id)}"]`);
        const isOpen = !menu.hidden;
        closeAllMessageMenus();
        if (menu && !isOpen) menu.hidden = false;
      });
    });

    els.messageThread.querySelectorAll("[data-action-delete-message]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const id = button.dataset.actionDeleteMessage;
        if (!confirm("Delete this encrypted message? This cannot be undone.")) return;
        try {
          await api(`/api/messenger/messages/${id}`, { method: "DELETE" });
          if (state.currentConversation) {
            await loadConversation(state.currentConversation.id);
          }
        } catch (error) {
          setMeta(error.message);
        }
      });
    });

    els.messageThread.querySelectorAll("[data-audio-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        const key = button.dataset.audioToggle;
        const audio = els.messageThread.querySelector(`[data-audio-source="${CSS.escape(key)}"]`);
        if (!audio) return;
        const shouldPlay = audio.paused;
        els.messageThread.querySelectorAll("[data-audio-source]").forEach((candidate) => candidate.pause());
        els.messageThread.querySelectorAll("[data-audio-toggle]").forEach((candidate) => {
          candidate.textContent = "▶";
        });
        if (shouldPlay) {
          audio.play();
          button.textContent = "❚❚";
        } else {
          audio.pause();
          button.textContent = "▶";
        }
        audio.onended = () => {
          button.textContent = "▶";
        };
      });
    });

    if (forceScrollBottom || wasNearBottom) {
      els.messageThread.scrollTop = els.messageThread.scrollHeight;
    } else {
      els.messageThread.scrollTop = previousScrollTop;
    }

    return decrypted;
  };

  const loadConversation = async (conversationId, options = {}) => {
    const { forceScrollBottom = false } = options;
    const currentSeq = state.conversationLoadSeq;
    const data = await api(`/api/messenger/conversations/${conversationId}/messages`);
    if (currentSeq !== state.conversationLoadSeq) return;
    if (!data.conversation) {
      renderEmptyThread("Conversation unavailable", "This conversation is hidden by your privacy settings.");
      return;
    }
    state.currentConversation = data.conversation;
    els.conversationTitle.textContent = data.conversation.name;
    renderContacts();
    renderAddMemberOptions();
    const decrypted = await renderMessages(data.messages, { forceScrollBottom });
    if (currentSeq !== state.conversationLoadSeq) return;
    const sendingBlocked = Boolean(data.conversation.sending_blocked);
    els.messageInput.disabled = sendingBlocked;
    els.sendBtn.disabled = sendingBlocked;
    els.recordBtn.disabled = sendingBlocked;
    const notices = [];
    if (data.conversation.visibility_notice) notices.push(data.conversation.visibility_notice);
    if (data.blocked_by_user_count) notices.push(`${data.blocked_by_user_count} message(s) hidden by your block list.`);
    if (data.blocked_by_ca_count) notices.push(`${data.blocked_by_ca_count} message(s) blocked by CA policy.`);
    if (sendingBlocked) notices.push("This direct chat is blocked. You can read history but cannot send new messages.");
    notices.push(`${data.messages.length} encrypted item(s) loaded for this conversation.`);
    setMeta(notices.join(" "));

    state.conversationRenderCache[conversationId] = {
      conversation: data.conversation,
      decryptedMessages: decrypted,
      blockedByUserCount: data.blocked_by_user_count || 0,
      blockedByCaCount: data.blocked_by_ca_count || 0,
    };
  };

  const selectConversation = async (conversationId) => {
    const seq = ++state.conversationLoadSeq;

    // Immediately clear current view so the user knows switching is happening
    els.messageThread.innerHTML = "";
    els.conversationTitle.textContent = "Loading...";
    els.messageInput.disabled = true;
    els.sendBtn.disabled = true;
    els.recordBtn.disabled = true;

    if (state.socket && state.joinedConversationId && Number(state.joinedConversationId) !== Number(conversationId)) {
      state.socket.emit("messenger:leave_conversation", { conversation_id: state.joinedConversationId });
      state.joinedConversationId = null;
    }

    const cached = state.conversationRenderCache[conversationId];
    if (cached) {
      if (seq !== state.conversationLoadSeq) return;
      state.currentConversation = cached.conversation;
      els.conversationTitle.textContent = cached.conversation.name;
      renderContacts();
      renderAddMemberOptions();
      await renderMessages(cached.decryptedMessages, { forceScrollBottom: true, preDecrypted: true });
      if (seq !== state.conversationLoadSeq) return;

      const sendingBlocked = Boolean(cached.conversation.sending_blocked);
      els.messageInput.disabled = sendingBlocked;
      els.sendBtn.disabled = sendingBlocked;
      els.recordBtn.disabled = sendingBlocked;
      setMeta("Loaded cached chat instantly. Syncing latest messages...");

      if (state.socket && Number(state.joinedConversationId) !== Number(conversationId)) {
        state.socket.emit("messenger:join_conversation", { conversation_id: conversationId });
        state.joinedConversationId = conversationId;
      }
      loadConversation(conversationId).catch((error) => setMeta(error.message));
      return;
    }

    renderEmptyThread("Decrypting messages...", "Loading the conversation and unwrapping your local copy of each AES key.");
    setMeta("Loading secure conversation...");
    if (state.socket && Number(state.joinedConversationId) !== Number(conversationId)) {
      state.socket.emit("messenger:join_conversation", { conversation_id: conversationId });
      state.joinedConversationId = conversationId;
    }
    await loadConversation(conversationId, { forceScrollBottom: true });
  };

  const openDirectConversation = async (username) => {
    const data = await api("/api/messenger/conversations/direct", {
      method: "POST",
      body: JSON.stringify({ username }),
    });
    await fetchConversations();
    await selectConversation(data.conversation.id);
  };

  const updateAttachmentBar = () => {
    els.clearAttachmentBtn.hidden = !state.pendingAttachment;
    els.recordBtn.classList.toggle("is-recording", state.pendingAttachment?.kind === "voice" || state.mediaRecorder?.state === "recording");
  };

  const createPayloadObject = () => {
    const text = els.messageInput.value.trim();
    if (!state.pendingAttachment) {
      return { kind: "text", text };
    }
    return {
      kind: state.pendingAttachment.kind,
      text,
      file_name: state.pendingAttachment.fileName,
      mime_type: state.pendingAttachment.mimeType,
      hash: state.pendingAttachment.hash,
      data_base64: state.pendingAttachment.dataBase64,
    };
  };

  const encryptForConversation = async (payloadObject) => {
    const members = await Promise.all(state.currentConversation.members.map((username) => ensurePublicKeys(username).then((keys) => ({ username, keys }))));
    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = textEncoder.encode(JSON.stringify(payloadObject));
    const encryptedBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aesKey, plaintext);
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const tag = encryptedBytes.slice(encryptedBytes.length - 16);
    const signature = await crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      state.localKeys.signingPrivateKey,
      ciphertext
    );

    const recipients = await Promise.all(
      members.map(async ({ username, keys }) => ({
        username,
        encrypted_aes_key: arrayBufferToBase64(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, keys.encryptionKey, rawAesKey)),
      }))
    );

    return {
      encrypted_payload: arrayBufferToBase64(ciphertext),
      nonce: arrayBufferToBase64(nonce),
      tag: arrayBufferToBase64(tag),
      signature: arrayBufferToBase64(signature),
      recipients,
    };
  };

  const sendMessage = async (event) => {
    event.preventDefault();
    if (!state.currentConversation) return;

    const text = els.messageInput.value.trim();
    if (!text && !state.pendingAttachment) return;

    const payloadObject = createPayloadObject();
    const encrypted = await encryptForConversation(payloadObject);

    await api("/api/messenger/messages", {
      method: "POST",
      body: JSON.stringify({
        conversation_id: state.currentConversation.id,
        message_type: payloadObject.kind,
        file_name: payloadObject.file_name || null,
        file_mime_type: payloadObject.mime_type || null,
        file_size: state.pendingAttachment?.size || null,
        file_hash: payloadObject.hash || null,
        ...encrypted,
      }),
    });

    els.messageInput.value = "";
    els.messageInput.style.height = "56px";
    state.pendingAttachment = null;
    updateAttachmentBar();
    setMeta("Message encrypted locally and delivered with per-member AES key wrapping.");
    await loadConversation(state.currentConversation.id, { forceScrollBottom: true });
    await fetchConversations();
  };

  const handleFileSelection = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    const buffer = await file.arrayBuffer();
    state.pendingAttachment = {
      kind: "file",
      fileName: file.name,
      mimeType: file.type || "application/octet-stream",
      size: file.size,
      hash: await computeSha256(buffer),
      dataBase64: arrayBufferToBase64(buffer),
    };
    updateAttachmentBar();
  };

  const toggleRecording = async () => {
    if (state.mediaRecorder?.state === "recording") {
      state.mediaRecorder.stop();
      return;
    }

    if (!navigator.mediaDevices?.getUserMedia || !window.MediaRecorder) {
      setMeta("Voice notes are not supported in this browser.");
      return;
    }

    state.mediaChunks = [];
    state.mediaStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    state.mediaRecorder = new MediaRecorder(state.mediaStream);
    els.recordBtn.classList.add("is-recording");
    setMeta("Recording voice note... click the mic again to stop.");

    state.mediaRecorder.addEventListener("dataavailable", (e) => {
      if (e.data.size) {
        state.mediaChunks.push(e.data);
      }
    });

    state.mediaRecorder.addEventListener("stop", async () => {
      const blob = new Blob(state.mediaChunks, { type: state.mediaRecorder.mimeType || "audio/webm" });
      const buffer = await blob.arrayBuffer();
      state.pendingAttachment = {
        kind: "voice",
        fileName: `voice-note-${Date.now()}.webm`,
        mimeType: blob.type || "audio/webm",
        size: buffer.byteLength,
        hash: await computeSha256(buffer),
        dataBase64: arrayBufferToBase64(buffer),
      };
      state.mediaStream?.getTracks().forEach((track) => track.stop());
      els.recordBtn.classList.remove("is-recording");
      updateAttachmentBar();
      setMeta("Voice note captured and ready for encrypted delivery.");
    });

    state.mediaRecorder.start();
  };

  const createGroup = async (event) => {
    event.preventDefault();
    const name = els.groupName.value.trim();
    const data = await api("/api/messenger/conversations/group", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    els.groupForm.reset();
    await fetchConversations();
    await selectConversation(data.conversation.id);
  };

  const addGroupMember = async () => {
    if (!state.currentConversation?.is_group) return;
    const username = state.addMemberChoice;
    if (!username) {
      setMeta("No eligible user to add in this group.");
      return;
    }
    await api(`/api/messenger/conversations/${state.currentConversation.id}/members`, {
      method: "POST",
      body: JSON.stringify({ username }),
    });
    await fetchUsers();
    await fetchConversations();
    els.addMemberPopover.hidden = true;
    await loadConversation(state.currentConversation.id);
  };

  const refreshData = async () => {
    if (state.refreshInFlight) return state.refreshInFlight;
    state.refreshInFlight = (async () => {
      await Promise.all([fetchUsers(), fetchConversations()]);
      if (state.currentConversation) {
        if (!getConversationById(state.currentConversation.id)) {
          if (state.socket && state.joinedConversationId) {
            state.socket.emit("messenger:leave_conversation", { conversation_id: state.joinedConversationId });
            state.joinedConversationId = null;
          }
          state.currentConversation = null;
          els.conversationTitle.textContent = "Choose a chat";
          els.messageInput.disabled = true;
          els.sendBtn.disabled = true;
          els.recordBtn.disabled = true;
          renderEmptyThread("Conversation hidden", "A privacy block hid this conversation from your account.");
          setMeta("Conversation list updated.");
          return;
        }
        await loadConversation(state.currentConversation.id);
      }
    })();
    try {
      await state.refreshInFlight;
    } finally {
      state.refreshInFlight = null;
    }
  };

  const init = async () => {
    if (!window.crypto?.subtle) {
      renderEmptyThread("Browser not supported", "Use a modern browser with Web Crypto enabled.");
      return;
    }

    state.localKeys = await ensureLocalKeys();
    await registerPublicKeys();
    ensureSocket();
    const ca = await api("/api/messenger/ca");
    setStatus("Device keys loaded. X.509 identity certificates.");
    setMeta(`Trusted CA loaded: ${ca.issuer}`);
    await fetchUsers();
    await fetchConversations();

    const firstConversation = state.conversations[0];
    if (firstConversation) {
      await selectConversation(firstConversation.id);
    } else {
      renderEmptyThread("No chats yet", "Start a direct chat from the left panel or create your first encrypted group.");
    }

    state.poller = window.setInterval(() => {
      refreshData().catch(() => {
        setMeta("Background refresh failed. Retrying soon.");
      });
    }, 5000);
  };

  els.composeForm.addEventListener("submit", (event) => {
    sendMessage(event).catch((error) => setMeta(error.message));
  });
  els.refreshUsersBtn.addEventListener("click", () => refreshData().catch((error) => setMeta(error.message)));
  els.groupForm.addEventListener("submit", (event) => createGroup(event).catch((error) => setMeta(error.message)));
  els.addMemberBtn.addEventListener("click", () => addGroupMember().catch((error) => setMeta(error.message)));
  els.addMemberToggle?.addEventListener("click", () => {
    closeAllContactMenus();
    els.addMemberPopover.hidden = !els.addMemberPopover.hidden;
    closeAddMemberOptions();
  });
  els.addMemberPickerBtn?.addEventListener("click", (event) => {
    event.stopPropagation();
    if (els.addMemberPopover.hidden) return;
    if (els.addMemberPickerBtn.disabled) return;
    els.addMemberOptions.hidden = !els.addMemberOptions.hidden;
  });
  els.attachBtn.addEventListener("click", () => els.fileInput.click());
  els.fileInput.addEventListener("change", (event) => handleFileSelection(event).catch((error) => setMeta(error.message)));
  els.recordBtn.addEventListener("click", () => toggleRecording().catch((error) => setMeta(error.message)));
  els.clearAttachmentBtn.addEventListener("click", () => {
    state.pendingAttachment = null;
    els.fileInput.value = "";
    updateAttachmentBar();
  });
  document.addEventListener("click", (event) => {
    if (!els.addMemberWrap?.contains(event.target)) {
      els.addMemberPopover.hidden = true;
      closeAddMemberOptions();
    }
    if (!event.target.closest("[data-card-wrap]")) {
      closeAllContactMenus();
      closeAllMessageMenus();
    }
    if (!event.target.closest(".messenger-bubble-menu-wrap")) {
      closeAllMessageMenus();
    }
  });
  els.messageInput.addEventListener("input", () => {
    els.messageInput.style.height = "56px";
    els.messageInput.style.height = `${Math.min(els.messageInput.scrollHeight, 140)}px`;
  });
  els.messageInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      els.composeForm.requestSubmit();
    }
  });
  window.addEventListener("beforeunload", () => {
    if (state.socket && state.joinedConversationId) {
      state.socket.emit("messenger:leave_conversation", { conversation_id: state.joinedConversationId });
    }
    state.socket?.disconnect();
    if (state.poller) window.clearInterval(state.poller);
    state.mediaStream?.getTracks().forEach((track) => track.stop());
  });

  init().catch((error) => {
    setStatus(error.message);
    renderEmptyThread("Setup error", error.message);
  });
}
