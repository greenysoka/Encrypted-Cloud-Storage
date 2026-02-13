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

const arrayBufferToBase64 = (buffer) => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
};

function getHpw() {
  return localStorage.getItem('hpw') || '';
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

const MOBILE_FILE_NAME_BREAKPOINT = 650;
const TABLET_FILE_NAME_BREAKPOINT = 1024;
const MOBILE_FILE_NAME_MAX_CHARS = 52;
const TABLET_FILE_NAME_MAX_CHARS = 78;
const DESKTOP_FILE_NAME_MAX_CHARS = 96;
let responsiveFileNameResizeBound = false;
let responsiveFileNameResizeTimer = null;

function truncateMiddle(text, maxChars) {
  if (!text || text.length <= maxChars) return text || '';
  const marker = '...';
  if (maxChars <= marker.length) return '.'.repeat(maxChars);
  const keep = maxChars - marker.length;
  const start = Math.ceil(keep / 2);
  const end = Math.floor(keep / 2);
  return `${text.slice(0, start)}${marker}${text.slice(text.length - end)}`;
}

function splitFileName(fileName) {
  const lastDot = fileName.lastIndexOf('.');
  if (lastDot <= 0 || lastDot === fileName.length - 1) {
    return { base: fileName, ext: '' };
  }
  const ext = fileName.slice(lastDot);
  if (ext.length > 15) {
    return { base: fileName, ext: '' };
  }
  return { base: fileName.slice(0, lastDot), ext };
}

function truncateFileName(fileName, maxChars) {
  if (!fileName || fileName.length <= maxChars) return fileName || '';
  const { base, ext } = splitFileName(fileName);
  if (!ext) return truncateMiddle(fileName, maxChars);

  const maxBaseChars = maxChars - ext.length;
  if (maxBaseChars <= 8) return truncateMiddle(fileName, maxChars);
  return `${truncateMiddle(base, maxBaseChars)}${ext}`;
}

function getResponsiveFileName(fileName) {
  if (!fileName) return '';
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  if (viewportWidth <= MOBILE_FILE_NAME_BREAKPOINT) {
    return truncateFileName(fileName, MOBILE_FILE_NAME_MAX_CHARS);
  }
  if (viewportWidth <= TABLET_FILE_NAME_BREAKPOINT) {
    return truncateFileName(fileName, TABLET_FILE_NAME_MAX_CHARS);
  }
  return truncateFileName(fileName, DESKTOP_FILE_NAME_MAX_CHARS);
}

function setResponsiveFileName(el, fullName) {
  if (!el) return;
  const safeName = String(fullName || '');
  el.dataset.fullName = safeName;
  el.title = safeName;
  el.textContent = getResponsiveFileName(safeName);
}

function applyResponsiveFileNames(root = document) {
  root.querySelectorAll('.file-name[data-full-name]').forEach((el) => {
    const fullName = el.dataset.fullName || '';
    el.textContent = getResponsiveFileName(fullName);
    el.title = fullName;
  });
}

function setupResponsiveFileNameResize() {
  if (responsiveFileNameResizeBound) return;
  responsiveFileNameResizeBound = true;
  window.addEventListener('resize', () => {
    clearTimeout(responsiveFileNameResizeTimer);
    responsiveFileNameResizeTimer = setTimeout(() => {
      applyResponsiveFileNames(document);
    }, 80);
  });
}

function setHint(el, message, isError = false) {
  if (!el) return;
  el.textContent = message;
  el.hidden = !message;
  el.classList.toggle("error", isError);
}

function updateSearchPlaceholder(totalFiles) {
  const searchInput = document.getElementById("file-search");
  if (!searchInput) return;
  const count = Number(totalFiles || 0);
  if (count <= 0) {
    searchInput.placeholder = "Search files...";
    return;
  }
  const suffix = count === 1 ? "item" : "items";
  searchInput.placeholder = `Search in ${count} ${suffix}...`;
}

async function handleLogin() {
  const form = document.getElementById("login-form");
  if (!form) return;
  const passwordInput = document.getElementById("password");
  const totpInput = document.getElementById("totp-code");
  const errorEl = document.getElementById("login-error");
  const loginBtn = document.getElementById("login-cta");

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
    if (loginBtn) {
      loginBtn.textContent = "Unlocking...";
      loginBtn.disabled = true;
    }
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
        if (loginBtn) {
          loginBtn.textContent = "Unlock";
          loginBtn.disabled = false;
        }
        return;
      }
      localStorage.setItem('hpw', hpw);
      window.location.href = "/";
    } catch (err) {
      setHint(errorEl, "Login failed. Try again.", true);
      if (loginBtn) {
        loginBtn.textContent = "Unlock";
        loginBtn.disabled = false;
      }
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
      localStorage.setItem('hpw', hpw);
      window.location.href = "/";
    } catch (err) {
      setHint(errorEl, "Setup failed. Try again.", true);
    }
  });
}

function setupDropZone() {
  const dropZone = document.getElementById("drop-zone");
  const input = document.getElementById("file-input");
  const queueEl = document.getElementById("upload-queue");
  if (!dropZone || !input) return;

  let activeUploads = 0;

  const createUploadItem = (file) => {
    const item = document.createElement("div");
    item.className = "upload-item";
    item.innerHTML = `
      <div class="upload-info">
        <div class="upload-header">
          <div class="upload-name">${file.name}</div>
          <div class="upload-pct">0%</div>
        </div>
        <div class="progress-track">
          <div class="progress-bar"></div>
        </div>
      </div>
    `;
    queueEl.appendChild(item);
    return item;
  };

  const updateItem = (item, pct, isError = false, isSuccess = false, errorMsg = "") => {
    const bar = item.querySelector(".progress-bar");
    const label = item.querySelector(".upload-pct");
    if (bar) bar.style.width = `${pct}%`;
    if (label) {
      if (isError) label.textContent = errorMsg || "Error";
      else if (isSuccess) label.textContent = "Done";
      else label.textContent = `${Math.round(pct)}%`;
    }
    if (isError) item.classList.add("error");
    if (isSuccess) item.classList.add("success");
  };



  const uploadFileChunked = async (file, item, encryptedBytes, plaintextSize) => {
    const CHUNK_SIZE = 720 * 1024;
    const totalChunks = Math.ceil(encryptedBytes.length / CHUNK_SIZE);

    const initRes = await fetch("/upload/init", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: file.name,
        mime: file.type || "application/octet-stream",
        size: plaintextSize,
        total_chunks: totalChunks,
        folder_id: currentFolderId || "",
      }),
    });
    if (initRes.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
    const initData = await initRes.json();
    if (!initData.ok) throw new Error(initData.error || "Init failed");
    const uploadId = initData.upload_id;

    for (let i = 0; i < totalChunks; i++) {
      const start = i * CHUNK_SIZE;
      const end = Math.min(start + CHUNK_SIZE, encryptedBytes.length);
      const chunkBytes = encryptedBytes.subarray(start, end);

      let binary = '';
      for (let j = 0; j < chunkBytes.length; j++) {
        binary += String.fromCharCode(chunkBytes[j]);
      }
      const chunkBase64 = btoa(binary);

      const chunkRes = await fetch("/upload/chunk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          upload_id: uploadId,
          index: i,
          data: chunkBase64,
        }),
      });
      if (chunkRes.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
      const chunkResult = await chunkRes.json();
      if (!chunkResult.ok) throw new Error(chunkResult.error || "Chunk failed");

      const chunkProgress = 30 + ((i + 1) / totalChunks) * 65;
      updateItem(item, chunkProgress);
    }

    const completeRes = await fetch("/upload/complete", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ upload_id: uploadId }),
    });
    if (completeRes.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
    const completeData = await completeRes.json();
    if (!completeData.ok) throw new Error(completeData.error || "Complete failed");

    updateItem(item, 100, false, true);
  };

  const uploadFileSingle = (file, item, encryptedBytes, plaintextSize) => {
    return new Promise((resolve, reject) => {
      let binary = '';
      for (let i = 0; i < encryptedBytes.length; i++) {
        binary += String.fromCharCode(encryptedBytes[i]);
      }
      const b64 = btoa(binary);

      const xhr = new XMLHttpRequest();
      xhr.open("POST", "/upload");
      xhr.setRequestHeader("Content-Type", "application/json");

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const percentComplete = (e.loaded / e.total) * 70 + 30;
          updateItem(item, percentComplete);
        }
      };

      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          const payload = JSON.parse(xhr.responseText);
          if (payload.ok) {
            updateItem(item, 100, false, true);
            resolve();
          } else {
            updateItem(item, 100, true, false, payload.error);
            console.error(payload.error);
            reject(new Error(payload.error));
          }
        } else {
          updateItem(item, 100, true, false, `Upload failed (${xhr.status})`);
          reject(new Error(`HTTP ${xhr.status}`));
        }
      };

      xhr.onerror = () => {
        updateItem(item, 100, true, false, "Network error");
        reject(new Error("Network error"));
      };

      xhr.send(JSON.stringify({
        data: b64,
        name: file.name,
        mime: file.type || "application/octet-stream",
        size: plaintextSize,
        total_chunks: 1,
        folder_id: currentFolderId || "",
      }));
    });
  };

  const uploadFile = async (file) => {
    if (!file) return;
    const hpw = getHpw();
    if (!hpw) {
      window.location.href = "/login";
      return;
    }

    activeUploads++;
    const item = createUploadItem(file);
    updateItem(item, 0);

    const encryptProgress = (p) => updateItem(item, p * 0.3);

    try {
      encryptProgress(10);
      const plaintext = await file.arrayBuffer();
      encryptProgress(50);
      const encryptedBuffer = await encryptFile(hpw, plaintext);
      const encryptedBytes = new Uint8Array(encryptedBuffer);
      encryptProgress(100);

      const CHUNK_THRESHOLD = 720 * 1024;

      if (encryptedBytes.length > CHUNK_THRESHOLD) {
        await uploadFileChunked(file, item, encryptedBytes, plaintext.byteLength);
      } else {
        await uploadFileSingle(file, item, encryptedBytes, plaintext.byteLength);
      }
    } catch (err) {
      updateItem(item, 0, true, false, err.message || "Upload failed");
      console.error(err);
    } finally {
      activeUploads--;
      if (activeUploads === 0) {
        setTimeout(() => { window.location.reload(); }, 1000);
      }
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
    if (input.files && input.files.length > 0) {
      Array.from(input.files).forEach(uploadFile);
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
    const files = event.dataTransfer.files;
    if (files && files.length > 0) {
      Array.from(files).forEach(uploadFile);
    }
  });
}

function setupLockButton() {
  const lockBtn = document.getElementById("lock-btn");
  if (!lockBtn) return;
  lockBtn.addEventListener("click", async () => {
    localStorage.removeItem('hpw');
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
    const emptyState = document.getElementById("empty-state");

    let visibleFolders = (window.folderData || []).filter(f => {
      const parentId = f.parent_id || null;
      if (parentId !== currentFolderId) return false;
      if (query) {
        const name = (f.display_name || '').toLowerCase();
        return name.includes(query);
      }
      return true;
    });

    visibleFolders.sort((a, b) => {
      const nameA = (a.display_name || '').toLowerCase();
      const nameB = (b.display_name || '').toLowerCase();
      return nameA.localeCompare(nameB);
    });

    let visible = window.fileData.filter(file => {
      const fileFolderId = file.folder_id || null;
      if (fileFolderId !== currentFolderId) return false;

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

    const renderId = ++currentRenderId;
    thumbnailQueue = [];
    list.innerHTML = '';

    renderFolderCards(visibleFolders, list);
    renderFileList(visible, list);

    updateSearchPlaceholder(visible.length + visibleFolders.length);

    if (noResults) {
      noResults.hidden = visible.length !== 0 || visibleFolders.length !== 0;
    }
    if (emptyState) {
      emptyState.hidden = visible.length !== 0 || visibleFolders.length !== 0 || currentFolderId;
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
const THUMBNAIL_CACHE_DB = 'encrypted-cloud-thumbnail-cache';
const THUMBNAIL_CACHE_STORE = 'thumbnails';
const THUMBNAIL_CACHE_MAX_ENTRIES = 500;
let thumbnailDbPromise = null;
let thumbnailCacheUnavailable = false;
let thumbnailPruneRunning = false;

function openThumbnailCacheDb() {
  if (thumbnailCacheUnavailable || typeof window === 'undefined' || !window.indexedDB) {
    return Promise.resolve(null);
  }
  if (thumbnailDbPromise) return thumbnailDbPromise;

  thumbnailDbPromise = new Promise((resolve) => {
    const req = indexedDB.open(THUMBNAIL_CACHE_DB, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(THUMBNAIL_CACHE_STORE)) {
        const store = db.createObjectStore(THUMBNAIL_CACHE_STORE, { keyPath: 'key' });
        store.createIndex('created_at', 'created_at', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => {
      thumbnailCacheUnavailable = true;
      resolve(null);
    };
    req.onblocked = () => {
      thumbnailCacheUnavailable = true;
      resolve(null);
    };
  });

  return thumbnailDbPromise;
}

function getThumbnailCacheKey(file, hpw) {
  if (!file || !file.id || !hpw) return '';
  const size = Number(file.size || 0);
  const uploadedAt = file.uploaded_at || '';
  const mime = file.mime || '';
  return `${hpw}:${file.id}:${size}:${uploadedAt}:${mime}`;
}

async function getCachedThumbnail(cacheKey) {
  if (!cacheKey) return null;
  const db = await openThumbnailCacheDb();
  if (!db) return null;

  return new Promise((resolve) => {
    const tx = db.transaction(THUMBNAIL_CACHE_STORE, 'readonly');
    const store = tx.objectStore(THUMBNAIL_CACHE_STORE);
    const req = store.get(cacheKey);

    req.onsuccess = () => {
      const record = req.result;
      if (!record || !record.data_url) {
        resolve(null);
        return;
      }
      resolve(record.data_url);
    };
    req.onerror = () => resolve(null);
  });
}

async function setCachedThumbnail(cacheKey, dataUrl) {
  if (!cacheKey || !dataUrl) return;
  const db = await openThumbnailCacheDb();
  if (!db) return;

  await new Promise((resolve) => {
    const tx = db.transaction(THUMBNAIL_CACHE_STORE, 'readwrite');
    const store = tx.objectStore(THUMBNAIL_CACHE_STORE);
    const req = store.put({
      key: cacheKey,
      data_url: dataUrl,
      created_at: Date.now(),
    });
    req.onsuccess = () => resolve(true);
    req.onerror = () => resolve(false);
  });
}

async function pruneThumbnailCache() {
  if (thumbnailPruneRunning) return;
  thumbnailPruneRunning = true;

  try {
    const db = await openThumbnailCacheDb();
    if (!db) return;

    const total = await new Promise((resolve) => {
      const tx = db.transaction(THUMBNAIL_CACHE_STORE, 'readonly');
      const store = tx.objectStore(THUMBNAIL_CACHE_STORE);
      const req = store.count();
      req.onsuccess = () => resolve(req.result || 0);
      req.onerror = () => resolve(0);
    });

    const removeCount = total - THUMBNAIL_CACHE_MAX_ENTRIES;
    if (removeCount <= 0) return;

    await new Promise((resolve) => {
      let removed = 0;
      const tx = db.transaction(THUMBNAIL_CACHE_STORE, 'readwrite');
      const store = tx.objectStore(THUMBNAIL_CACHE_STORE);
      const index = store.index('created_at');
      const cursorReq = index.openCursor();

      cursorReq.onsuccess = (event) => {
        const cursor = event.target.result;
        if (!cursor || removed >= removeCount) {
          resolve(true);
          return;
        }
        store.delete(cursor.primaryKey);
        removed += 1;
        cursor.continue();
      };
      cursorReq.onerror = () => resolve(false);
    });
  } finally {
    thumbnailPruneRunning = false;
  }
}

async function reconcileThumbnailCache(files) {
  if (!Array.isArray(files)) return;
  const hpw = getHpw();
  if (!hpw) return;

  const db = await openThumbnailCacheDb();
  if (!db) return;

  const valid = new Set(
    files
      .filter((f) => f && f.mime && f.mime.startsWith('image/'))
      .map((f) => getThumbnailCacheKey(f, hpw))
      .filter(Boolean)
  );

  await new Promise((resolve) => {
    const prefix = `${hpw}:`;
    const tx = db.transaction(THUMBNAIL_CACHE_STORE, 'readwrite');
    const store = tx.objectStore(THUMBNAIL_CACHE_STORE);
    const cursorReq = store.openCursor();

    cursorReq.onsuccess = (event) => {
      const cursor = event.target.result;
      if (!cursor) {
        resolve(true);
        return;
      }
      const key = String(cursor.primaryKey || '');
      if (key.startsWith(prefix) && !valid.has(key)) {
        store.delete(cursor.primaryKey);
      }
      cursor.continue();
    };
    cursorReq.onerror = () => resolve(false);
  });
}

async function setImageSourceAndWait(img, src) {
  if (!img || !src) return;
  await new Promise((resolve) => {
    let finished = false;
    const done = () => {
      if (finished) return;
      finished = true;
      img.onload = null;
      img.onerror = null;
      resolve();
    };
    img.onload = done;
    img.onerror = done;
    img.src = src;
    if (img.complete) done();
    setTimeout(done, 3000);
  });
}

async function processThumbnailQueue() {
  if (isProcessingQueue) return;
  isProcessingQueue = true;

  const hpw = getHpw();

  while (thumbnailQueue.length > 0) {
    const task = thumbnailQueue.shift();
    const { img, preview, file, renderId } = task;
    const fileId = file?.id;

    if (renderId !== currentRenderId || !document.contains(preview)) continue;
    if (!fileId) continue;

    if (!hpw) {
      localStorage.removeItem('hpw');
      window.location.href = '/login';
      return;
    }

    try {
      const cacheKey = getThumbnailCacheKey(file, hpw);
      let thumbnailDataUrl = await getCachedThumbnail(cacheKey);

      if (!thumbnailDataUrl) {
        const res = await fetch(`/files/${fileId}`);
        if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
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

        thumbnailDataUrl = canvas.toDataURL('image/jpeg', 0.85);
        await setCachedThumbnail(cacheKey, thumbnailDataUrl);
        void pruneThumbnailCache();
      }

      if (thumbnailDataUrl) {
        await setImageSourceAndWait(img, thumbnailDataUrl);
      }
    } catch (e) {
    }

    img.classList.add('is-loaded');
  }

  isProcessingQueue = false;
}

window.addEventListener('scroll', () => {
  localStorage.setItem('scrollY', window.scrollY);
}, { passive: true });

let currentFolderId = null;
let folderPath = [];
window.folderData = [];

try {
  const saved = JSON.parse(localStorage.getItem('folderState') || 'null');
  if (saved && saved.id) {
    currentFolderId = saved.id;
    folderPath = saved.path || [];
  }
} catch (e) { }

setTimeout(() => renderBreadcrumbs(), 0);

function saveFolderState() {
  localStorage.setItem('folderState', JSON.stringify({ id: currentFolderId, path: folderPath }));
}

function navigateToFolder(folderId, folderName) {
  if (folderId === currentFolderId) return;

  if (!folderId) {
    currentFolderId = null;
    folderPath = [];
  } else {
    const idx = folderPath.findIndex(f => f.id === folderId);
    if (idx >= 0) {
      folderPath = folderPath.slice(0, idx + 1);
    } else {
      folderPath.push({ id: folderId, name: folderName });
    }
    currentFolderId = folderId;
  }

  saveFolderState();
  renderBreadcrumbs();
  if (window.applyFilters) window.applyFilters();
}

function renderBreadcrumbs() {
  const bar = document.getElementById('breadcrumb-bar');
  if (!bar) return;
  bar.innerHTML = '';

  const rootBtn = document.createElement('button');
  rootBtn.className = 'breadcrumb-item breadcrumb-root' + (!currentFolderId ? ' active' : '');
  rootBtn.dataset.folderId = '';
  rootBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg> Root`;
  rootBtn.addEventListener('click', () => navigateToFolder(null, null));
  bar.appendChild(rootBtn);

  folderPath.forEach((f, i) => {
    const sep = document.createElement('span');
    sep.className = 'breadcrumb-separator';
    sep.textContent = '›';
    bar.appendChild(sep);

    const btn = document.createElement('button');
    btn.className = 'breadcrumb-item' + (i === folderPath.length - 1 ? ' active' : '');
    btn.dataset.folderId = f.id;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> ${f.name}`;
    btn.addEventListener('click', () => navigateToFolder(f.id, f.name));
    bar.appendChild(btn);
  });

  bar.scrollLeft = bar.scrollWidth;
}

function countFolderContents(folderId) {
  if (!window.fileData || !window.folderData) return 0;
  const files = window.fileData.filter(f => (f.folder_id || null) === folderId);
  const subfolders = window.folderData.filter(f => (f.parent_id || null) === folderId);
  return files.length + subfolders.length;
}

function renderFolderCards(folders, container) {
  const template = document.getElementById('folder-card-template');
  if (!template) return;

  folders.forEach(folder => {
    const clone = template.content.cloneNode(true);
    const card = clone.querySelector('.folder-card');

    card.dataset.fileId = folder.id;
    card.dataset.folderId = folder.id;
    card.dataset.displayName = folder.display_name || 'Folder';
    card.dataset.type = 'folder';

    const nameEl = card.querySelector('.file-name');
    nameEl.textContent = folder.display_name || 'Folder';

    const metaEl = card.querySelector('.file-meta');
    const count = countFolderContents(folder.id);
    metaEl.textContent = `${count} item${count !== 1 ? 's' : ''}`;

    card.addEventListener('click', (e) => {
      if (e.target.closest('.file-menu')) return;
      if (window._isSelectionMode) {
        e.preventDefault();
        e.stopPropagation();
        window._toggleSelectCard(card);
        return;
      }
      navigateToFolder(folder.id, folder.display_name || 'Folder');
    });

    container.appendChild(clone);
  });
}

function renderFileList(files, container) {
  const renderId = ++currentRenderId;
  thumbnailQueue = [];

  const template = document.getElementById('file-card-template');
  const emptyState = document.getElementById('empty-state');

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
    card.dataset.fileMime = file.mime || "";

    const preview = card.querySelector('.file-preview');

    if (file.mime && file.mime.startsWith('image/')) {
      const img = document.createElement('img');
      img.alt = file.display_name;
      img.loading = 'lazy';

      preview.appendChild(img);

      thumbnailQueue.push({
        img,
        preview,
        file,
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

    const fileNameEl = card.querySelector('.file-name');
    setResponsiveFileName(fileNameEl, file.display_name || file.alias || 'file');
    const metaText = `${file.mime} · ${formatSize(file.size)}`;
    card.querySelector('.file-details .file-meta:not(.uploaded-at)').textContent = metaText;

    card.querySelector('.uploaded-at').textContent = 'Uploaded ' + formatDate(file.uploaded_at);

    const downloadBtn = card.querySelector('.download-btn');
    downloadBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const hpw = getHpw();
      if (!hpw) { window.location.href = '/login'; return; }
      try {
        const res = await fetch(`/files/${file.id}`);
        if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
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

    card.addEventListener('click', (e) => {
      if (!window._isSelectionMode) return;
      if (e.target.closest('.file-menu') || e.target.closest('.select-cb')) return;
      e.preventDefault();
      window._toggleSelectCard(card);
    });

    container.appendChild(clone);
  });

  setupAnimations();
  applyResponsiveFileNames(container);

  const savedScroll = localStorage.getItem('scrollY');
  if (savedScroll) {
    window.scrollTo(0, parseInt(savedScroll));
  }
  processThumbnailQueue();
}

async function fetchFiles() {
  const list = document.getElementById("file-list");
  const emptyState = document.getElementById("empty-state");
  const loading = document.getElementById("loading-indicator");

  try {
    const res = await fetch('/api/files');
    if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
    if (!res.ok) throw new Error('Failed to load files');
    const data = await res.json();

    const allItems = data.files || [];
    window.folderData = allItems.filter(f => f.type === 'folder');
    window.fileData = allItems.filter(f => f.type !== 'folder');

    void reconcileThumbnailCache(window.fileData);
    void pruneThumbnailCache();
    updateSearchPlaceholder(window.fileData.length);

    if (loading) loading.remove();

    if (window.fileData.length === 0 && window.folderData.length === 0) {
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

function closeAllFileActionMenus() {
  document.querySelectorAll('.file-menu').forEach((menu) => {
    const toggleBtn = menu.querySelector('.file-menu-toggle');
    const popup = menu.querySelector('.file-menu-popup');
    if (!popup) return;
    popup.hidden = true;
    if (toggleBtn) toggleBtn.setAttribute('aria-expanded', 'false');
  });
}

function setupFileActionMenus() {
  document.addEventListener("click", (event) => {
    const toggleBtn = event.target.closest(".file-menu-toggle");
    if (toggleBtn) {
      const menu = toggleBtn.closest(".file-menu");
      const popup = menu?.querySelector(".file-menu-popup");
      if (!popup) return;
      const shouldOpen = popup.hidden;
      closeAllFileActionMenus();
      if (shouldOpen) {
        popup.hidden = false;
        toggleBtn.setAttribute("aria-expanded", "true");
      }
      return;
    }

    closeAllFileActionMenus();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeAllFileActionMenus();
    }
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

function setupImagePreviewModal() {
  const modal = document.getElementById("image-preview-modal");
  if (!modal) return;

  const closeBtn = document.getElementById("close-image-preview");
  const titleEl = document.getElementById("image-preview-title");
  const hintEl = document.getElementById("image-preview-hint");
  const imageEl = document.getElementById("image-preview-img");
  let currentObjectUrl = null;
  let requestVersion = 0;

  const revokeImageUrl = () => {
    if (!currentObjectUrl) return;
    URL.revokeObjectURL(currentObjectUrl);
    currentObjectUrl = null;
  };

  const setLoadingState = (message = "Loading preview...", isError = false) => {
    if (hintEl) {
      hintEl.textContent = message;
      hintEl.hidden = !message;
      hintEl.classList.toggle("error", isError);
    }
    if (imageEl) {
      imageEl.hidden = true;
      imageEl.removeAttribute("src");
    }
    revokeImageUrl();
  };

  const closeModal = () => {
    requestVersion += 1;
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    setLoadingState("Loading preview...");
  };

  const openModal = (name) => {
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    if (titleEl) titleEl.textContent = name || "Image Preview";
    setLoadingState("Loading preview...");
  };

  const openImageFromCard = async (card) => {
    const fileId = card?.dataset?.fileId;
    if (!fileId) return;

    const fileName = card.dataset.displayName || card.dataset.fileName || "Image Preview";
    const mime = card.dataset.fileMime || "application/octet-stream";
    openModal(fileName);

    const hpw = getHpw();
    if (!hpw) {
      localStorage.removeItem("hpw");
      window.location.href = "/login";
      return;
    }

    const thisRequest = ++requestVersion;

    try {
      const res = await fetch(`/files/${fileId}`);
      if (res.status === 401) {
        localStorage.removeItem("hpw");
        window.location.href = "/login";
        return;
      }
      if (!res.ok) throw new Error("Fetch failed");

      const encryptedBuf = await res.arrayBuffer();
      const decrypted = await decryptFile(hpw, encryptedBuf);
      if (thisRequest !== requestVersion) return;

      const blob = new Blob([decrypted], { type: mime });
      const objectUrl = URL.createObjectURL(blob);
      revokeImageUrl();
      currentObjectUrl = objectUrl;

      if (imageEl) {
        imageEl.src = objectUrl;
        imageEl.alt = fileName;
        imageEl.hidden = false;
      }
      if (hintEl) {
        hintEl.hidden = true;
        hintEl.classList.remove("error");
      }
    } catch (err) {
      if (thisRequest !== requestVersion) return;
      if (hintEl) {
        hintEl.textContent = "Could not load image preview.";
        hintEl.hidden = false;
        hintEl.classList.add("error");
      }
    }
  };

  document.addEventListener("click", (event) => {
    const clickedImage = event.target.closest(".file-preview img");
    if (clickedImage) {
      const card = clickedImage.closest(".file-card");
      if (!card) return;
      openImageFromCard(card);
      return;
    }

    if (event.target.closest("#close-image-preview")) {
      closeModal();
      return;
    }

    if (event.target.closest("#image-preview-modal [data-close='true']")) {
      closeModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && modal.classList.contains("is-open")) {
      closeModal();
    }
  });

  closeBtn?.addEventListener("click", closeModal);
}

function setupSettingsPopup() {
  const btn = document.getElementById("settings-btn");
  const popup = document.getElementById("settings-popup");
  const themeSelect = document.getElementById("theme-select");
  const saveBtn = document.getElementById("save-settings-btn");
  const statusEl = document.getElementById("settings-status");

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

  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const maxUpload = document.getElementById("settings-max-upload")?.value;
      const maxStorage = document.getElementById("settings-max-storage")?.value;
      const sessionHours = document.getElementById("settings-session-hours")?.value;

      saveBtn.disabled = true;
      saveBtn.textContent = "Saving...";
      if (statusEl) statusEl.hidden = true;

      try {
        const res = await fetch("/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            max_upload_mb: maxUpload ? parseInt(maxUpload) : undefined,
            max_storage_mb: maxStorage ? parseInt(maxStorage) : undefined,
            session_hours: sessionHours ? parseInt(sessionHours) : undefined,
          }),
        });
        const payload = await res.json();

        if (res.ok && payload.ok) {
          if (statusEl) {
            statusEl.textContent = "Saved! Reloading...";
            statusEl.hidden = false;
            statusEl.classList.remove("error");
          }
          setTimeout(() => window.location.reload(), 800);
        } else {
          throw new Error(payload.error || "Failed to save");
        }
      } catch (err) {
        console.error(err);
        if (statusEl) {
          statusEl.textContent = err.message || "Error saving settings";
          statusEl.hidden = false;
          statusEl.classList.add("error");
        }
        saveBtn.disabled = false;
        saveBtn.textContent = "Save Changes";
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
setupFileActionMenus();
setupDeleteModal();
setupRenameModal();
setupImagePreviewModal();
setupAnimations();
setupResponsiveFileNameResize();
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


function setupCreateFolderModal() {
  const modal = document.getElementById("create-folder-modal");
  if (!modal) return;
  const input = document.getElementById("folder-name-input");
  const confirmBtn = document.getElementById("confirm-create-folder");
  const cancelBtn = document.getElementById("cancel-create-folder");
  const triggerBtn = document.getElementById("new-folder-btn");

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    if (input) input.value = "";
  };

  const openModal = () => {
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
    if (input) { input.value = ""; input.focus(); }
  };

  triggerBtn?.addEventListener("click", openModal);
  cancelBtn?.addEventListener("click", closeModal);
  modal.querySelector('[data-close]')?.addEventListener("click", closeModal);

  const handleCreate = async () => {
    const name = (input?.value || "").trim();
    if (!name) return;

    try {
      const res = await fetch("/folders", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, parent_id: currentFolderId || "" }),
      });
      if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
      const data = await res.json();
      if (!data.ok) { alert(data.error || "Failed to create folder"); return; }
      closeModal();
      await fetchFiles();
    } catch (err) {
      console.error(err);
      alert("Failed to create folder.");
    }
  };

  confirmBtn?.addEventListener("click", handleCreate);
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") handleCreate();
    if (e.key === "Escape") closeModal();
  });
}

function setupDeleteFolderModal() {
  const modal = document.getElementById("delete-folder-modal");
  if (!modal) return;
  const message = document.getElementById("delete-folder-message");
  const confirmBtn = document.getElementById("confirm-delete-folder");
  const cancelBtn = document.getElementById("cancel-delete-folder");
  let pendingId = null;

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    pendingId = null;
  };

  const openModal = (folderId, name) => {
    pendingId = folderId;
    if (message) {
      message.textContent = `Are you sure you want to delete "${name}" and all its contents? This cannot be undone.`;
    }
    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
  };

  document.addEventListener("click", (event) => {
    if (event.target.closest(".delete-folder-btn")) {
      const btn = event.target.closest(".delete-folder-btn");
      const card = btn.closest(".folder-card");
      if (!card) return;
      openModal(card.dataset.folderId, card.dataset.displayName || "this folder");
    }
  });

  cancelBtn?.addEventListener("click", closeModal);
  modal.querySelector('[data-close]')?.addEventListener("click", closeModal);

  const handleDelete = async () => {
    if (!pendingId) return;
    try {
      const res = await fetch(`/folders/${pendingId}`, { method: "DELETE" });
      if (!res.ok) {
        try { const d = await res.json(); alert(d.error || "Delete failed."); }
        catch (e) { alert("Delete failed."); }
      } else {
        closeModal();
        await fetchFiles();
      }
    } catch (err) {
      console.error(err);
      alert("Delete failed.");
    }
  };

  confirmBtn?.addEventListener("click", handleDelete);
}

function setupRenameFolderModal() {

  const modal = document.getElementById("rename-modal");
  if (!modal) return;
  const input = document.getElementById("rename-input");
  let pendingFolderId = null;

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    pendingFolderId = null;
    if (input) input.value = "";
  };

  document.addEventListener("click", (event) => {
    if (event.target.closest(".rename-folder-btn")) {
      const btn = event.target.closest(".rename-folder-btn");
      const card = btn.closest(".folder-card");
      if (!card) return;
      pendingFolderId = card.dataset.folderId;
      const name = card.dataset.displayName || "";
      if (input) input.value = name;
      modal.classList.add("is-open");
      modal.setAttribute("aria-hidden", "false");
      if (input) input.focus();
    }
  });

  const confirmBtn = document.getElementById("confirm-rename");
  confirmBtn?.addEventListener("click", async (e) => {
    if (!pendingFolderId || !input) return;
    e.stopImmediatePropagation();
    const newName = input.value.trim();
    if (!newName) return;

    try {
      const res = await fetch(`/folders/${pendingFolderId}/rename`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newName }),
      });
      if (!res.ok) { alert("Rename failed."); return; }
      closeModal();
      const pathEntry = folderPath.find(f => f.id === pendingFolderId);
      if (pathEntry) pathEntry.name = newName;
      renderBreadcrumbs();
      await fetchFiles();
    } catch (err) {
      console.error(err);
      alert("Rename failed.");
    }
  }, true);
}

function setupMoveModal() {
  const modal = document.getElementById("move-modal");
  if (!modal) return;
  const folderList = document.getElementById("move-folder-list");
  const confirmBtn = document.getElementById("confirm-move");
  const cancelBtn = document.getElementById("cancel-move");
  let pendingItemId = null;
  let pendingItemType = null;
  let selectedTargetId = null;

  const closeModal = () => {
    modal.classList.remove("is-open");
    modal.setAttribute("aria-hidden", "true");
    pendingItemId = null;
    pendingItemType = null;
    selectedTargetId = null;
  };

  const openModal = (itemId, itemType, currentParent) => {
    pendingItemId = itemId;
    pendingItemType = itemType;
    selectedTargetId = null;

    if (!folderList) return;
    folderList.innerHTML = '';

    const rootBtn = document.createElement('button');
    rootBtn.className = 'move-folder-item root-item' + (!currentParent ? ' selected' : '');
    rootBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg> Root`;
    rootBtn.addEventListener('click', () => {
      folderList.querySelectorAll('.move-folder-item').forEach(b => b.classList.remove('selected'));
      rootBtn.classList.add('selected');
      selectedTargetId = null;
    });
    if (!currentParent) selectedTargetId = null;
    folderList.appendChild(rootBtn);

    const folders = (window.folderData || []).filter(f => f.id !== itemId);
    folders.forEach(folder => {
      const btn = document.createElement('button');
      const isSelected = (folder.id === currentParent);
      btn.className = 'move-folder-item folder-item' + (isSelected ? ' selected' : '');
      btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> ${folder.display_name || 'Folder'}`;
      btn.addEventListener('click', () => {
        folderList.querySelectorAll('.move-folder-item').forEach(b => b.classList.remove('selected'));
        btn.classList.add('selected');
        selectedTargetId = folder.id;
      });
      if (isSelected) selectedTargetId = folder.id;
      folderList.appendChild(btn);
    });

    modal.classList.add("is-open");
    modal.setAttribute("aria-hidden", "false");
  };

  document.addEventListener("click", (event) => {
    if (event.target.closest(".move-btn")) {
      const btn = event.target.closest(".move-btn");
      const card = btn.closest(".file-card");
      if (!card) return;
      const itemId = card.dataset.fileId || card.dataset.folderId;
      const itemType = card.dataset.type === 'folder' ? 'folder' : 'file';
      const currentParent = itemType === 'folder'
        ? (window.folderData || []).find(f => f.id === itemId)?.parent_id
        : (window.fileData || []).find(f => f.id === itemId)?.folder_id;
      openModal(itemId, itemType, currentParent || null);
    }
  });

  cancelBtn?.addEventListener("click", closeModal);
  modal.querySelector('[data-close]')?.addEventListener("click", closeModal);

  const handleMove = async () => {
    if (!pendingItemId) return;

    try {
      const res = await fetch(`/files/${pendingItemId}/move`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_folder_id: selectedTargetId || "" }),
      });
      if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
      const data = await res.json();
      if (!data.ok) { alert(data.error || "Move failed."); return; }
      closeModal();
      await fetchFiles();
    } catch (err) {
      console.error(err);
      alert("Move failed.");
    }
  };

  confirmBtn?.addEventListener("click", handleMove);
}

setupCreateFolderModal();
setupDeleteFolderModal();
setupRenameFolderModal();
setupMoveModal();

if (document.getElementById('file-list')) {
  fetchFiles();
}

function setupSelectionMode() {
  const selectBtn = document.getElementById('select-mode-btn');
  const fileList = document.getElementById('file-list');
  const toolbar = document.getElementById('batch-toolbar');
  const countEl = document.getElementById('batch-count');
  const selectAllBtn = document.getElementById('batch-select-all');
  const batchDeleteBtn = document.getElementById('batch-delete-btn');
  const batchMoveBtn = document.getElementById('batch-move-btn');

  const batchModal = document.getElementById('batch-delete-modal');
  const batchMsg = document.getElementById('batch-delete-message');
  const confirmBatchDelete = document.getElementById('confirm-batch-delete');
  const cancelBatchDelete = document.getElementById('cancel-batch-delete');

  if (!selectBtn || !fileList) return;

  const selectedItems = new Set();
  window._isSelectionMode = false;

  const updateToolbar = () => {
    const count = selectedItems.size;
    if (toolbar) {
      toolbar.hidden = !window._isSelectionMode;
    }
    if (countEl) {
      countEl.textContent = `${count} selected`;
    }
    if (batchDeleteBtn) batchDeleteBtn.disabled = count === 0;
    if (batchMoveBtn) batchMoveBtn.disabled = count === 0;

    const allCards = fileList.querySelectorAll('.file-card');
    const allSelected = allCards.length > 0 && allCards.length === count;
    if (selectAllBtn) {
      selectAllBtn.textContent = allSelected ? 'Deselect All' : 'Select All';
    }
  };

  const toggleSelectCard = (card) => {
    const id = card.dataset.fileId || card.dataset.folderId;
    if (!id) return;
    const cb = card.querySelector('.select-cb');
    if (selectedItems.has(id)) {
      selectedItems.delete(id);
      card.classList.remove('selected');
      if (cb) cb.checked = false;
    } else {
      selectedItems.add(id);
      card.classList.add('selected');
      if (cb) cb.checked = true;
    }
    updateToolbar();
  };

  window._toggleSelectCard = toggleSelectCard;

  const enterSelectionMode = () => {
    window._isSelectionMode = true;
    fileList.classList.add('selection-mode');
    selectBtn.classList.add('active');
    selectBtn.title = 'Exit selection';
    updateToolbar();
  };

  const exitSelectionMode = () => {
    window._isSelectionMode = false;
    fileList.classList.remove('selection-mode');
    selectBtn.classList.remove('active');
    selectBtn.title = 'Select items';
    selectedItems.clear();
    fileList.querySelectorAll('.file-card.selected').forEach(c => c.classList.remove('selected'));
    fileList.querySelectorAll('.select-cb').forEach(cb => { cb.checked = false; });
    if (toolbar) toolbar.hidden = true;
  };

  selectBtn.addEventListener('click', () => {
    if (window._isSelectionMode) {
      exitSelectionMode();
    } else {
      enterSelectionMode();
    }
  });

  fileList.addEventListener('change', (e) => {
    if (!window._isSelectionMode) return;
    const cb = e.target.closest('.select-cb');
    if (!cb) return;
    const card = cb.closest('.file-card');
    if (!card) return;
    const id = card.dataset.fileId || card.dataset.folderId;
    if (!id) return;
    if (cb.checked) {
      selectedItems.add(id);
      card.classList.add('selected');
    } else {
      selectedItems.delete(id);
      card.classList.remove('selected');
    }
    updateToolbar();
  });

  if (selectAllBtn) {
    selectAllBtn.addEventListener('click', () => {
      const allCards = fileList.querySelectorAll('.file-card');
      const allSelected = allCards.length > 0 && allCards.length === selectedItems.size;
      if (allSelected) {
        selectedItems.clear();
        allCards.forEach(card => {
          card.classList.remove('selected');
          const cb = card.querySelector('.select-cb');
          if (cb) cb.checked = false;
        });
      } else {
        allCards.forEach(card => {
          const id = card.dataset.fileId || card.dataset.folderId;
          if (id) {
            selectedItems.add(id);
            card.classList.add('selected');
            const cb = card.querySelector('.select-cb');
            if (cb) cb.checked = true;
          }
        });
      }
      updateToolbar();
    });
  }

  const closeBatchDeleteModal = () => {
    if (batchModal) {
      batchModal.classList.remove('is-open');
      batchModal.setAttribute('aria-hidden', 'true');
    }
  };

  if (batchDeleteBtn) {
    batchDeleteBtn.addEventListener('click', () => {
      if (selectedItems.size === 0) return;
      if (batchMsg) {
        batchMsg.textContent = `Are you sure you want to delete ${selectedItems.size} item${selectedItems.size !== 1 ? 's' : ''}? This cannot be undone.`;
      }
      if (batchModal) {
        batchModal.classList.add('is-open');
        batchModal.setAttribute('aria-hidden', 'false');
      }
    });
  }

  cancelBatchDelete?.addEventListener('click', closeBatchDeleteModal);
  batchModal?.querySelector('[data-close]')?.addEventListener('click', closeBatchDeleteModal);

  if (confirmBatchDelete) {
    confirmBatchDelete.addEventListener('click', async () => {
      if (selectedItems.size === 0) return;
      confirmBatchDelete.disabled = true;
      confirmBatchDelete.textContent = 'Deleting...';
      try {
        const res = await fetch('/batch/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ids: [...selectedItems] }),
        });
        if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
        const data = await res.json();
        if (!data.ok) {
          alert(data.error || 'Batch delete failed.');
        } else {
          closeBatchDeleteModal();
          exitSelectionMode();
          await fetchFiles();
        }
      } catch (err) {
        console.error(err);
        alert('Batch delete failed.');
      }
      confirmBatchDelete.disabled = false;
      confirmBatchDelete.textContent = 'Delete All';
    });
  }

  if (batchMoveBtn) {
    batchMoveBtn.addEventListener('click', () => {
      if (selectedItems.size === 0) return;

      const moveModal = document.getElementById('move-modal');
      const folderList = document.getElementById('move-folder-list');
      const confirmMove = document.getElementById('confirm-move');
      const cancelMove = document.getElementById('cancel-move');
      const moveTitle = document.getElementById('move-title');
      if (!moveModal || !folderList) return;

      if (moveTitle) moveTitle.textContent = `Move ${selectedItems.size} item${selectedItems.size !== 1 ? 's' : ''}`;

      let selectedTargetId = null;
      folderList.innerHTML = '';

      const rootBtn = document.createElement('button');
      rootBtn.className = 'move-folder-item root-item selected';
      rootBtn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg> Root`;
      rootBtn.addEventListener('click', () => {
        folderList.querySelectorAll('.move-folder-item').forEach(b => b.classList.remove('selected'));
        rootBtn.classList.add('selected');
        selectedTargetId = null;
      });
      folderList.appendChild(rootBtn);

      const folders = (window.folderData || []).filter(f => !selectedItems.has(f.id));
      folders.forEach(folder => {
        const btn = document.createElement('button');
        btn.className = 'move-folder-item folder-item';
        btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg> ${folder.display_name || 'Folder'}`;
        btn.addEventListener('click', () => {
          folderList.querySelectorAll('.move-folder-item').forEach(b => b.classList.remove('selected'));
          btn.classList.add('selected');
          selectedTargetId = folder.id;
        });
        folderList.appendChild(btn);
      });

      moveModal.classList.add('is-open');
      moveModal.setAttribute('aria-hidden', 'false');

      const batchMoveHandler = async () => {
        try {
          const res = await fetch('/batch/move', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              ids: [...selectedItems],
              target_folder_id: selectedTargetId || '',
            }),
          });
          if (res.status === 401) { localStorage.removeItem('hpw'); window.location.href = '/login'; return; }
          const data = await res.json();
          if (!data.ok) {
            alert(data.error || 'Move failed.');
            return;
          }
          moveModal.classList.remove('is-open');
          moveModal.setAttribute('aria-hidden', 'true');
          exitSelectionMode();
          await fetchFiles();
        } catch (err) {
          console.error(err);
          alert('Move failed.');
        }
        confirmMove?.removeEventListener('click', batchMoveHandler);
      };

      const newConfirm = confirmMove.cloneNode(true);
      confirmMove.parentNode.replaceChild(newConfirm, confirmMove);
      newConfirm.addEventListener('click', batchMoveHandler);

      const closeBatchMove = () => {
        moveModal.classList.remove('is-open');
        moveModal.setAttribute('aria-hidden', 'true');
        newConfirm.removeEventListener('click', batchMoveHandler);
        const restored = newConfirm.cloneNode(true);
        restored.id = 'confirm-move';
        newConfirm.parentNode.replaceChild(restored, newConfirm);
        setupMoveModal();
      };

      const newCancel = cancelMove.cloneNode(true);
      cancelMove.parentNode.replaceChild(newCancel, cancelMove);
      newCancel.addEventListener('click', closeBatchMove);

      const backdrop = moveModal.querySelector('[data-close]');
      if (backdrop) {
        const newBackdrop = backdrop.cloneNode(true);
        backdrop.parentNode.replaceChild(newBackdrop, backdrop);
        newBackdrop.addEventListener('click', closeBatchMove);
      }
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && window._isSelectionMode) {
      exitSelectionMode();
    }
  });
}

setupSelectionMode();
