async function sha256Hex(message) {
  const data = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

async function deriveKey(hpwHex, salt) {
  const hpwBytes = hexToBytes(hpwHex);
  const keyMaterial = await crypto.subtle.importKey(
    "raw", hpwBytes, "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt, iterations: 600000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptFile(hpwHex, plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(hpwHex, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce }, key, plaintext
  );
  const result = new Uint8Array(salt.length + nonce.length + ciphertext.byteLength);
  result.set(salt, 0);
  result.set(nonce, salt.length);
  result.set(new Uint8Array(ciphertext), salt.length + nonce.length);
  return result.buffer;
}

async function decryptFile(hpwHex, blob) {
  const data = new Uint8Array(blob);
  if (data.length < 28) throw new Error("Corrupted ciphertext");
  const salt = data.slice(0, 16);
  const nonce = data.slice(16, 28);
  const ciphertext = data.slice(28);
  const key = await deriveKey(hpwHex, salt);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce }, key, ciphertext
  );
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function getHpw() {
  return sessionStorage.getItem('hpw') || '';
}

const formatSize = (bytes) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const formatDate = (dateString = '') => {
  if (!dateString) return '';
  const d = new Date(dateString);
  return d.toLocaleString();
};

function setHint(el, message, isError = false) {
  if (!el) return;
  el.textContent = message;
  el.hidden = !message;
  el.classList.toggle("error", isError);
}

async function handleLogin() {
  const form = document.getElementById("login-form");
  if (!form) return;
  const passwordInput = document.getElementById("password");
  const totpInput = document.getElementById("totp-code");
  const errorEl = document.getElementById("login-error");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = passwordInput.value.trim();
    if (!password) {
      setHint(errorEl, "Enter your password.", true);
      return;
    }
    const code = totpInput?.value.trim() || "";
    if (!code) {
      setHint(errorEl, "Enter your authenticator code.", true);
      return;
    }
    setHint(errorEl, "Unlocking...");
    try {
      const hpw = await sha256Hex(password);
      const res = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hpw, totp: code, client_time: Date.now() }),
      });
      const payload = await res.json();
      if (!res.ok || !payload.ok) {
        let msg = payload.error || "Login failed";
        if (payload.drift_sec !== undefined && payload.drift_sec !== null) {
          msg += ` (Clock drift ~${payload.drift_sec}s)`;
        }
        setHint(errorEl, msg, true);
        return;
      }
      sessionStorage.setItem('hpw', hpw);
      window.location.href = "/";
    } catch (err) {
      setHint(errorEl, "Login failed. Try again.", true);
    }
  });
}

async function handleSetup() {
  const form = document.getElementById("setup-form");
  if (!form) return;
  const root = document.getElementById("setup-root");
  const passwordInput = document.getElementById("password");
  const totpInput = document.getElementById("totp-code");
  const totpField = document.getElementById("totp-field");
  const totpSetup = document.getElementById("totp-setup");
  const totpSecret = document.getElementById("totp-secret");
  const totpQr = document.getElementById("totp-qr");
  const cta = document.getElementById("setup-cta");
  const errorEl = document.getElementById("setup-error");

  const phase = root?.dataset.phase || "password";
  let stage = phase === "totp" ? "confirm" : "init";

  if (phase === "totp") {
    if (totpField) totpField.hidden = false;
  }

  const showSetupUI = (secret, qrData, message) => {
    if (totpField) totpField.hidden = false;
    if (totpSetup) totpSetup.hidden = false;
    if (totpSecret) totpSecret.textContent = secret || "";
    if (totpQr) totpQr.src = qrData || `/totp/qr?ts=${Date.now()}`;
    if (totpInput) totpInput.value = "";
    if (cta) cta.textContent = "Verify & Enter";
    if (message) {
      setHint(errorEl, message);
    } else {
      setHint(errorEl, "Scan the QR and enter your 6-digit code.");
    }
    stage = "confirm";
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const password = passwordInput.value.trim();
    if (!password) {
      setHint(errorEl, "Enter your password.", true);
      return;
    }
    if (stage !== "init") {
      const code = totpInput?.value.trim() || "";
      if (!code) {
        setHint(errorEl, "Enter your authenticator code.", true);
        return;
      }
    }
    setHint(errorEl, stage === "init" ? "Preparing 2FA setup..." : "Setting up...");
    try {
      const hpw = await sha256Hex(password);
      const totp = totpInput?.value.trim() || "";

      let body = { hpw, totp, client_time: Date.now() };

      if (stage === "init") {
        const maxUpload = document.getElementById("max-upload")?.value;
        const maxStorage = document.getElementById("max-storage")?.value;
        const sessionHours = document.getElementById("session-hours")?.value;

        body = {
          hpw,
          client_time: Date.now(),
          max_upload_mb: maxUpload ? parseInt(maxUpload) : 200,
          max_storage_mb: maxStorage ? parseInt(maxStorage) : 1000,
          session_hours: sessionHours ? parseInt(sessionHours) : 8
        };
      }
      const res = await fetch("/setup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const payload = await res.json();
      if (payload.setup) {
        showSetupUI(payload.totp_secret, payload.totp_qr, payload.message);
        return;
      }
      if (!res.ok || !payload.ok) {
        let msg = payload.error || "Setup failed";
        if (payload.drift_sec !== undefined && payload.drift_sec !== null) {
          msg += ` (Clock drift ~${payload.drift_sec}s)`;
        }
        setHint(errorEl, msg, true);
        return;
      }
      sessionStorage.setItem('hpw', hpw);
      window.location.href = "/";
    } catch (err) {
      setHint(errorEl, "Setup failed. Try again.", true);
    }
  });
}

function setupDropZone() {
  const dropZone = document.getElementById("drop-zone");
  const input = document.getElementById("file-input");
  const statusEl = document.getElementById("upload-status");
  if (!dropZone || !input) return;

  const uploadFile = async (file) => {
    if (!file) return;
    const hpw = getHpw();
    if (!hpw) {
      setHint(statusEl, "Session expired. Please unlock again.", true);
      return;
    }
    setHint(statusEl, `Encrypting ${file.name}...`);
    try {
      const plaintext = await file.arrayBuffer();
      const encrypted = await encryptFile(hpw, plaintext);
      const b64 = arrayBufferToBase64(encrypted);
      setHint(statusEl, `Uploading ${file.name}...`);
      const res = await fetch("/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          data: b64,
          name: file.name,
          mime: file.type || "application/octet-stream",
          size: plaintext.byteLength
        })
      });
      const payload = await res.json();
      if (!res.ok || !payload.ok) {
        setHint(statusEl, payload.error || "Upload failed", true);
        return;
      }
      setHint(statusEl, "Upload complete.");
      window.location.reload();
    } catch (err) {
      setHint(statusEl, "Upload failed. Try again.", true);
    }
  };

  dropZone.addEventListener("click", (event) => {
    if (event.target === input) return;
    input.click();
  });
  input.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  input.addEventListener("change", () => {
    if (input.files && input.files[0]) {
      uploadFile(input.files[0]);
      input.value = "";
    }
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropZone.classList.add("is-dragging");
    });
  });

  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropZone.classList.remove("is-dragging");
    });
  });

  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer.files[0];
    if (file) {
      uploadFile(file);
    }
  });
}

function setupLockButton() {
  const lockBtn = document.getElementById("lock-btn");
  if (!lockBtn) return;
  lockBtn.addEventListener("click", async () => {
    sessionStorage.removeItem('hpw');
    await fetch("/logout", { method: "POST" });
    window.location.href = "/login";
  });
}

function setupFilters() {
  const list = document.getElementById("file-list");
  if (!list) return;
  const cards = Array.from(list.querySelectorAll(".file-card"));
  const searchInput = document.getElementById("file-search");
  const dateFilter = document.getElementById("date-filter");
  const sizeFilter = document.getElementById("size-filter");
  const sortBy = document.getElementById("sort-by");
  const noResults = document.getElementById("no-results");

  const getUploadedTime = (card) => {
    const raw = card.dataset.uploaded || "";
    const ts = Date.parse(raw);
    return Number.isNaN(ts) ? 0 : ts;
  };

  const getSizeBytes = (card) => {
    const raw = card.dataset.size || "0";
    const size = Number.parseInt(raw, 10);
    return Number.isNaN(size) ? 0 : size;
  };

  const matchDate = (card, filter) => {
    if (filter === "all") return true;
    const now = Date.now();
    const uploaded = getUploadedTime(card);
    if (!uploaded) return false;
    let windowMs = 0;
    if (filter === "24h") windowMs = 24 * 60 * 60 * 1000;
    if (filter === "7d") windowMs = 7 * 24 * 60 * 60 * 1000;
    if (filter === "30d") windowMs = 30 * 24 * 60 * 60 * 1000;
    return uploaded >= now - windowMs;
  };

  const matchSize = (card, filter) => {
    if (filter === "all") return true;
    const mb = getSizeBytes(card) / (1024 * 1024);
    if (filter === "lt1") return mb < 1;
    if (filter === "1to10") return mb >= 1 && mb <= 10;
    if (filter === "10to100") return mb > 10 && mb <= 100;
    if (filter === "gt100") return mb > 100;
    return true;
  };

  const applyFilters = () => {
    const list = document.getElementById("file-list");
    if (!list) return;

    if (!window.fileData) return;

    const query = (searchInput?.value || "").trim().toLowerCase();
    const dateValue = dateFilter?.value || "all";
    const sizeValue = sizeFilter?.value || "all";
    const sortValue = sortBy?.value || "newest";

    let visible = window.fileData.filter(file => {
      const name = (file.display_name || file.alias || "").toLowerCase();
      const matchesQuery = !query || name.includes(query);

      let matchesDate = true;
      if (dateValue !== 'all') {
        const now = Date.now();
        const uploaded = Date.parse(file.uploaded_at);
        let windowMs = 0;
        if (dateValue === "24h") windowMs = 24 * 60 * 60 * 1000;
        if (dateValue === "7d") windowMs = 7 * 24 * 60 * 60 * 1000;
        if (dateValue === "30d") windowMs = 30 * 24 * 60 * 60 * 1000;
        matchesDate = uploaded >= now - windowMs;
      }

      let matchesSize = true;
      if (sizeValue !== 'all') {
        const mb = file.size / (1024 * 1024);
        if (sizeValue === "lt1") matchesSize = mb < 1;
        if (sizeValue === "1to10") matchesSize = mb >= 1 && mb <= 10;
        if (sizeValue === "10to100") matchesSize = mb > 10 && mb <= 100;
        if (sizeValue === "gt100") matchesSize = mb > 100;
      }

      return matchesQuery && matchesDate && matchesSize;
    });

    visible.sort((a, b) => {
      const sizeA = a.size || 0;
      const sizeB = b.size || 0;
      const dateA = Date.parse(a.uploaded_at || 0);
      const dateB = Date.parse(b.uploaded_at || 0);

      if (sortValue === "largest") return sizeB - sizeA;
      if (sortValue === "smallest") return sizeA - sizeB;
      if (sortValue === "oldest") return dateA - dateB;
      return dateB - dateA;
    });

    renderFileList(visible, list);

    if (noResults) {
      noResults.hidden = visible.length !== 0;
    }
  };

  const stopAnimations = () => {
    cards.forEach(c => c.classList.remove('appearing'));
  };

  [searchInput, dateFilter, sizeFilter, sortBy].forEach((control) => {
    if (!control) return;
    const eventName = control === searchInput ? "input" : "change";
    control.addEventListener(eventName, () => {
      stopAnimations();
      applyFilters();
    });
  });

  window.applyFilters = applyFilters;
}

let currentRenderId = 0;
let thumbnailQueue = [];
let isProcessingQueue = false;

async function processThumbnailQueue() {
  if (isProcessingQueue) return;
  isProcessingQueue = true;

  const hpw = getHpw();

  while (thumbnailQueue.length > 0) {
    const task = thumbnailQueue.shift();
    const { img, preview, fileId, renderId } = task;

    if (renderId !== currentRenderId || !document.contains(preview)) continue;

    if (!hpw) {
      img.classList.add('is-loaded');
      continue;
    }

    try {
      const res = await fetch(`/files/${fileId}`);
      if (!res.ok) throw new Error('Fetch failed');
      const encryptedBuf = await res.arrayBuffer();
      const decrypted = await decryptFile(hpw, encryptedBuf);

      const blob = new Blob([decrypted]);
      const bitmap = await createImageBitmap(blob);
      const maxDim = 200;
      let w = bitmap.width;
      let h = bitmap.height;
      if (w > maxDim || h > maxDim) {
        const scale = Math.min(maxDim / w, maxDim / h);
        w = Math.round(w * scale);
        h = Math.round(h * scale);
      }
      const canvas = document.createElement('canvas');
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(bitmap, 0, 0, w, h);
      bitmap.close();

      img.src = canvas.toDataURL('image/jpeg', 0.85);
      await new Promise((resolve) => {
        img.onload = resolve;
        img.onerror = resolve;
        setTimeout(resolve, 3000);
      });
    } catch (e) {
    }

    img.classList.add('is-loaded');
  }

  isProcessingQueue = false;
}

window.addEventListener('scroll', () => {
  localStorage.setItem('scrollY', window.scrollY);
}, { passive: true });

function renderFileList(files, container) {
  const renderId = ++currentRenderId;
  thumbnailQueue = [];

  const template = document.getElementById('file-card-template');
  const emptyState = document.getElementById('empty-state');
  container.innerHTML = '';

  if (files.length === 0) {
    return;
  }

  files.forEach((file) => {
    const clone = template.content.cloneNode(true);
    const card = clone.querySelector('.file-card');

    card.dataset.fileId = file.id;
    card.dataset.fileName = file.alias;
    card.dataset.displayName = file.display_name;
    card.dataset.size = file.size;
    card.dataset.uploaded = file.uploaded_at;

    const preview = card.querySelector('.file-preview');

    if (file.mime && file.mime.startsWith('image/')) {
      const img = document.createElement('img');
      img.alt = file.display_name;
      img.loading = 'lazy';

      preview.appendChild(img);

      thumbnailQueue.push({
        img,
        preview,
        fileId: file.id,
        renderId
      });

    } else {
      preview.classList.add('is-icon');
      preview.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"></path>
          <polyline points="14 2 14 8 20 8"></polyline>
        </svg>
      `;
    }

    card.querySelector('.file-name').textContent = file.display_name;
    const metaText = `${file.mime} · ${formatSize(file.size)}`;
    card.querySelector('.file-details .file-meta:not(.uploaded-at)').textContent = metaText;

    card.querySelector('.uploaded-at').textContent = 'Uploaded ' + formatDate(file.uploaded_at);

    const downloadBtn = card.querySelector('.download-btn');
    downloadBtn.removeAttribute('href');
    downloadBtn.style.cursor = 'pointer';
    downloadBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const hpw = getHpw();
      if (!hpw) { alert('Session expired. Please unlock again.'); return; }
      try {
        const res = await fetch(`/files/${file.id}`);
        if (!res.ok) throw new Error('Download failed');
        const encryptedBuf = await res.arrayBuffer();
        const decrypted = await decryptFile(hpw, encryptedBuf);
        const blob = new Blob([decrypted], { type: file.mime || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = file.display_name || file.alias || 'file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } catch (err) {
        console.error(err);
        alert('Download or decryption failed.');
      }
    });

    container.appendChild(clone);
  });

  setupAnimations();

  const savedScroll = localStorage.getItem('scrollY');
  if (savedScroll) {
    window.scrollTo(0, parseInt(savedScroll));
  }
  processThumbnailQueue();
}

async function fetchFiles() {
  const list = document.getElementById("file-list");
  const countEl = document.getElementById("file-count");
  const emptyState = document.getElementById("empty-state");
  const loading = document.getElementById("loading-indicator");

  try {
    const res = await fetch('/api/files');
    if (!res.ok) throw new Error('Failed to load files');
    const data = await res.json();

    window.fileData = data.files;

    if (countEl) countEl.textContent = `${window.fileData.length} files`;

    if (loading) loading.remove();

    if (window.fileData.length === 0) {
      if (emptyState) emptyState.hidden = false;
    } else {
      window.applyFilters();
    }

  } catch (err) {
    console.error(err);
    if (list) list.textContent = "Error loading files.";
  }
}

function setupAnimations() {
  const cards = document.querySelectorAll('.file-card.appearing');
  cards.forEach(card => {
    card.addEventListener('animationend', () => {
      card.classList.remove('appearing');
    });
  });
}


function setupImageLoading() {
  const images = document.querySelectorAll('.file-preview img');
  images.forEach(img => {
    if (img.complete) {
      img.classList.add('is-loaded');
    } else {
      img.addEventListener('load', () => {
        img.classList.add('is-loaded');
      });
      img.addEventListener('error', () => {
        img.classList.add('is-loaded');
      });
    }
  });
}

function setupDeleteModal() {
  const modal = document.getElementById("delete-modal");
  if (!modal) return;
  const message = document.getElementById("delete-message");
  const confirmBtn = document.getElementById("confirm-delete");
  const cancelBtn = document.getElementById("cancel-delete");
  let pendingId = null;

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    pendingId = null;
  };

  const openModal = (fileId, name) => {
    pendingId = fileId;
    if (message) {
      message.textContent = `Are you sure you want to delete ${name}? This cannot be undone.`;
    }
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
  };

  document.addEventListener("click", (event) => {
    if (event.target.closest(".delete-btn")) {
      const btn = event.target.closest(".delete-btn");
      const card = btn.closest(".file-card");
      if (!card) return;
      const fileId = card.dataset.fileId;
      const name = card.dataset.displayName || card.dataset.fileName || "this file";
      openModal(fileId, name);
    }
  });

  cancelBtn?.addEventListener("click", closeModal);

  const handleDelete = async () => {
    if (!pendingId) return;

    try {
      const res = await fetch(`/files/${pendingId}`, {
        method: "DELETE"
      });
      if (!res.ok) {
        try {
          const payload = await res.json();
          alert(payload.error || "Delete failed.");
        } catch (e) {
          alert("Delete failed.");
        }
      } else {
        window.location.reload();
      }
    } catch (err) {
      console.error(err);
      alert("Delete failed.");
    }
    closeModal();
  };

  confirmBtn?.addEventListener("click", handleDelete);
}

function setupRenameModal() {
  const modal = document.getElementById("rename-modal");
  if (!modal) return;
  const input = document.getElementById("rename-input");
  const confirmBtn = document.getElementById("confirm-rename");
  const cancelBtn = document.getElementById("cancel-rename");
  let pendingId = null;

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    pendingId = null;
    if (input) input.value = "";
  };

  const openModal = (fileId, currentName) => {
    pendingId = fileId;
    if (input) {

      const parts = currentName.split(".");
      if (parts.length > 1) {
        parts.pop();
        input.value = parts.join(".");
      } else {
        input.value = currentName;
      }
    }
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    if (input) input.focus();
  };

  document.addEventListener("click", (event) => {
    if (event.target.closest(".rename-btn")) {
      const btn = event.target.closest(".rename-btn");
      const card = btn.closest(".file-card");
      if (!card) return;
      const fileId = card.dataset.fileId;
      const name = card.dataset.displayName || card.dataset.fileName || "";
      openModal(fileId, name);
    }
  });

  closeModal();

  cancelBtn?.addEventListener("click", closeModal);

  const handleRename = async () => {
    if (!pendingId || !input) return;
    const newName = input.value.trim();
    if (!newName) return;

    try {
      const res = await fetch(`/files/${pendingId}/rename`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName }),
      });
      if (!res.ok) {
        setHint(document.getElementById("upload-status"), "Rename failed.", true);
      } else {
        window.location.reload();
      }
    } catch (err) {
      setHint(document.getElementById("upload-status"), "Rename failed.", true);
    }
    closeModal();
  };

  confirmBtn?.addEventListener("click", handleRename);
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleRename();
  });
}

function setupSettingsPopup() {
  const btn = document.getElementById("settings-btn");
  const popup = document.getElementById("settings-popup");
  const themeSelect = document.getElementById("theme-select");

  if (!btn || !popup) return;

  const savedTheme = localStorage.getItem("theme");
  if (themeSelect) {
    themeSelect.value = savedTheme || "";
    themeSelect.addEventListener("change", () => {
      const theme = themeSelect.value;
      if (theme) {
        document.documentElement.setAttribute("data-theme", theme);
        localStorage.setItem("theme", theme);
      } else {
        document.documentElement.removeAttribute("data-theme");
        localStorage.removeItem("theme");
      }
    });
  }

  const toggle = () => {
    const isHidden = popup.hidden;
    popup.hidden = !isHidden;
  };

  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    toggle();
  });

  document.addEventListener("click", (e) => {
    if (!popup.hidden && !popup.contains(e.target) && e.target !== btn) {
      popup.hidden = true;
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !popup.hidden) {
      popup.hidden = true;
      btn.focus();
    }
  });
}

handleLogin();
handleSetup();
setupDropZone();
setupLockButton();
setupFilters();
setupDeleteModal();
setupRenameModal();
setupAnimations();
function setupViewToggle() {
  const toggleBtn = document.getElementById("view-toggle");
  const list = document.getElementById("file-list");
  const iconList = document.getElementById("icon-list");
  const iconGrid = document.getElementById("icon-grid");

  if (!toggleBtn || !list) return;

  const setView = (mode) => {
    if (mode === "grid") {
      list.classList.add("grid-view");
      iconList.hidden = true;
      iconGrid.hidden = false;
    } else {
      list.classList.remove("grid-view");
      iconList.hidden = false;
      iconGrid.hidden = true;
    }
    localStorage.setItem("viewMode", mode);
  };

  const savedMode = localStorage.getItem("viewMode");
  if (savedMode) {
    setView(savedMode);
  }

  toggleBtn.addEventListener("click", () => {
    const isGrid = list.classList.contains("grid-view");
    setView(isGrid ? "list" : "grid");
  });
}

setupSettingsPopup();
setupViewToggle();
if (document.getElementById('file-list')) {
  fetchFiles();
}
