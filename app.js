(() => {
  'use strict';

  /* ────────────────────────────────────────────────────────────
     cookbook — static app hosted on GitHub Pages.
     Recipes   → data/recipes.json  (committed through the GitHub API)
     Pictures  → images/<id>.jpg    (committed through the GitHub API)
     Password  → encrypts the GitHub token stored in config.json.
                 It is asked once per device, then remembered.
     ──────────────────────────────────────────────────────────── */

  const API = 'https://api.github.com';
  const LS_TOKEN = 'cookbook.token';
  const LS_CFG = 'cookbook.cfg';
  const PBKDF2_ITERATIONS = 250000;

  const $ = (sel) => document.querySelector(sel);

  let cfg = null;          // { repo: "owner/name", branch: "main" }
  let token = null;
  let recipes = [];
  let recipesSha = null;
  let searchMode = 'all';
  let current = null;      // recipe shown in the detail dialog

  /* ───────── helpers ───────── */

  const utf8 = {
    enc: (s) => new TextEncoder().encode(s),
    dec: (b) => new TextDecoder().decode(b),
  };

  const b64 = {
    enc(buf) {
      const bytes = new Uint8Array(buf);
      let s = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      return btoa(s);
    },
    dec: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
  };

  const norm = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();

  function lines(text, numbered) {
    return text
      .split('\n')
      .map((l) => l.trim())
      .map((l) => l.replace(numbered ? /^(\d+[.)]|[-*•])\s+/ : /^[-*•]\s+/, ''))
      .filter(Boolean);
  }

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    Object.assign(node, props);
    node.append(...children);
    return node;
  }

  /* ───────── crypto: password ⇄ token ───────── */

  async function deriveKey(password, salt, iterations) {
    const base = await crypto.subtle.importKey('raw', utf8.enc(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptToken(password, plain) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, utf8.enc(plain));
    return { v: 1, iter: PBKDF2_ITERATIONS, salt: b64.enc(salt), iv: b64.enc(iv), data: b64.enc(data) };
  }

  async function decryptToken(password, vault) {
    const key = await deriveKey(password, b64.dec(vault.salt), vault.iter);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(vault.iv) }, key, b64.dec(vault.data));
    return utf8.dec(plain);
  }

  /* ───────── GitHub API ───────── */

  async function gh(path, opts = {}) {
    const headers = {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (opts.body) headers['Content-Type'] = 'application/json';

    const res = await fetch(API + path, { ...opts, headers, cache: 'no-store' });

    if (res.status === 401) {
      lockDevice();
      throw new Error('GitHub rejected the stored token. Please unlock again.');
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      const err = new Error(body.message || res.statusText);
      err.status = res.status;
      throw err;
    }
    return res.status === 204 ? null : res.json();
  }

  const contentsPath = (p) => `/repos/${cfg.repo}/contents/${p}`;

  async function getFile(path) {
    try {
      return await gh(`${contentsPath(path)}?ref=${encodeURIComponent(cfg.branch)}`);
    } catch (e) {
      if (e.status === 404) return null;
      throw e;
    }
  }

  function putFile(path, base64Content, message, sha) {
    return gh(contentsPath(path), {
      method: 'PUT',
      body: JSON.stringify({ message, content: base64Content, branch: cfg.branch, ...(sha ? { sha } : {}) }),
    });
  }

  /* ───────── recipes storage ───────── */

  async function loadRecipes() {
    const file = await getFile('data/recipes.json');
    if (!file) {
      recipes = [];
      recipesSha = null;
      return;
    }
    recipes = JSON.parse(utf8.dec(b64.dec(file.content)) || '[]');
    recipesSha = file.sha;
  }

  // Re-reads the latest file, applies the change, commits. Retries on conflict.
  async function commitRecipes(mutate, message) {
    for (let attempt = 0; attempt < 3; attempt++) {
      await loadRecipes();
      const next = mutate(recipes.slice());
      try {
        const res = await putFile(
          'data/recipes.json',
          b64.enc(utf8.enc(JSON.stringify(next, null, 2))),
          message,
          recipesSha
        );
        recipes = next;
        recipesSha = res.content.sha;
        return;
      } catch (e) {
        if (e.status !== 409 && e.status !== 422) throw e;
      }
    }
    throw new Error('Could not save (conflicting changes). Please try again.');
  }

  /* ───────── pictures ───────── */

  async function toBitmap(file) {
    if (window.createImageBitmap) {
      try {
        return await createImageBitmap(file, { imageOrientation: 'from-image' });
      } catch (_) { /* fall through */ }
    }
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      return img;
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  // Shrinks the photo (max 1280 px, JPEG) so the repo stays light and phones upload fast.
  async function prepareImage(file, max = 1280, quality = 0.82) {
    const bmp = await toBitmap(file);
    const w = bmp.width || bmp.naturalWidth;
    const h = bmp.height || bmp.naturalHeight;
    const scale = Math.min(1, max / Math.max(w, h));
    const canvas = document.createElement('canvas');
    canvas.width = Math.round(w * scale);
    canvas.height = Math.round(h * scale);
    canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
    return b64.enc(await blob.arrayBuffer());
  }

  function imageSrc(recipe) {
    return `https://raw.githubusercontent.com/${cfg.repo}/${cfg.branch}/${recipe.image}`;
  }

  function loadImage(img, recipe) {
    img.loading = 'lazy';
    img.alt = recipe.title;
    // Fallback to the GitHub Pages copy if raw.githubusercontent is unavailable.
    img.onerror = () => {
      img.onerror = null;
      img.src = recipe.image;
    };
    img.src = imageSrc(recipe);
  }

  /* ───────── gallery & search ───────── */

  function matches(recipe, terms) {
    const title = norm(recipe.title);
    const ingredients = recipe.ingredients.map(norm);
    return terms.every((t) => {
      const inTitle = title.includes(t);
      const inIngredients = ingredients.some((i) => i.includes(t));
      if (searchMode === 'title') return inTitle;
      if (searchMode === 'ingredients') return inIngredients;
      return inTitle || inIngredients;
    });
  }

  function renderGallery() {
    const terms = norm($('#search').value).split(/[\s,]+/).filter(Boolean);
    const list = recipes.filter((r) => matches(r, terms));
    const grid = $('#grid');
    grid.replaceChildren();

    if (!recipes.length) {
      $('#status').textContent = 'No recipe yet. Add your first one in the “+ New” tab.';
      return;
    }
    $('#status').textContent = list.length
      ? `${list.length} recipe${list.length > 1 ? 's' : ''}`
      : 'No recipe matches your search.';

    for (const r of list) {
      let thumb;
      if (r.image) {
        thumb = el('img', { className: 'thumb' });
        loadImage(thumb, r);
      } else {
        thumb = el('div', { className: 'thumb empty' }, '🍽️');
      }
      const card = el(
        'button',
        { className: 'card', type: 'button' },
        thumb,
        el('div', { className: 'info' },
          el('div', { className: 'name' }, r.title),
          el('div', { className: 'meta' }, `${r.ingredients.length} ingredients`))
      );
      card.addEventListener('click', () => openDetail(r));
      grid.append(card);
    }
  }

  function openDetail(r) {
    current = r;
    const img = $('#d-img');
    if (r.image) {
      loadImage(img, r);
      img.hidden = false;
    } else {
      img.hidden = true;
      img.removeAttribute('src');
    }
    $('#d-title').textContent = r.title;
    $('#d-ingredients').replaceChildren(...r.ingredients.map((i) => el('li', {}, i)));
    $('#d-steps').replaceChildren(...r.steps.map((s) => el('li', {}, s)));
    $('#detail').showModal();
    $('#detail').scrollTop = 0;
  }

  /* ───────── tabs ───────── */

  function showTab(name) {
    document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $('#tab-gallery').hidden = name !== 'gallery';
    $('#tab-create').hidden = name !== 'create';
  }

  /* ───────── screens ───────── */

  function show(which) {
    $('#lock').hidden = which !== 'lock';
    $('#setup').hidden = which !== 'setup';
    $('#app').hidden = which !== 'app';
  }

  async function start() {
    show('app');
    showTab('gallery');
    $('#status').textContent = 'Loading recipes…';
    try {
      await loadRecipes();
      renderGallery();
    } catch (e) {
      $('#status').textContent = `Could not load recipes: ${e.message}`;
    }
  }

  function lockDevice() {
    localStorage.removeItem(LS_TOKEN);
    localStorage.removeItem(LS_CFG);
    token = null;
    cfg = null;
    recipes = [];
    init();
  }

  function rememberDevice() {
    localStorage.setItem(LS_TOKEN, token);
    localStorage.setItem(LS_CFG, JSON.stringify(cfg));
  }

  /* ───────── init ───────── */

  async function init() {
    const savedToken = localStorage.getItem(LS_TOKEN);
    const savedCfg = JSON.parse(localStorage.getItem(LS_CFG) || 'null');
    if (savedToken && savedCfg) {
      token = savedToken;
      cfg = savedCfg;
      return start();
    }

    let remote = null;
    try {
      const res = await fetch(`config.json?t=${Date.now()}`, { cache: 'no-store' });
      if (res.ok) remote = await res.json();
    } catch (_) { /* no config yet */ }

    if (remote && remote.vault && remote.repo) {
      $('#lock').dataset.cfg = JSON.stringify(remote);
      show('lock');
      $('#lock-pass').focus();
    } else {
      $('#s-repo').value = $('#s-repo').value || guessRepo();
      show('setup');
    }
  }

  // owner.github.io/cookbook/  →  owner/cookbook
  function guessRepo() {
    const m = location.hostname.match(/^([^.]+)\.github\.io$/);
    if (!m) return '';
    const repo = location.pathname.split('/').filter(Boolean)[0] || `${m[1]}.github.io`;
    return `${m[1]}/${repo}`;
  }

  /* ───────── events ───────── */

  // Unlock (first connexion on this device)
  $('#lock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#lock-form button[type="submit"]');
    const err = $('#lock-error');
    err.textContent = '';
    btn.disabled = true;
    try {
      const remote = JSON.parse($('#lock').dataset.cfg);
      token = await decryptToken($('#lock-pass').value, remote.vault);
      cfg = { repo: remote.repo, branch: remote.branch || 'main' };
      rememberDevice();
      $('#lock-pass').value = '';
      await start();
    } catch (_) {
      err.textContent = 'Wrong password.';
      token = null;
    } finally {
      btn.disabled = false;
    }
  });

  // One-time setup
  $('#setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#setup-form button[type="submit"]');
    const err = $('#setup-error');
    err.textContent = '';

    const repo = $('#s-repo').value.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
    const pass = $('#s-pass').value;
    if (pass !== $('#s-pass2').value) {
      err.textContent = 'The passwords do not match.';
      return;
    }

    btn.disabled = true;
    btn.textContent = 'Setting up…';
    try {
      token = $('#s-token').value.trim();
      cfg = { repo, branch: 'main' };

      const info = await gh(`/repos/${repo}`);
      if (info.permissions && !info.permissions.push) throw new Error('This token cannot write to the repository.');
      cfg.branch = info.default_branch;

      const vault = await encryptToken(pass, token);
      const existing = await getFile('config.json');
      const config = { repo, branch: cfg.branch, vault };
      await putFile('config.json', b64.enc(utf8.enc(JSON.stringify(config, null, 2))), 'Set up cookbook', existing && existing.sha);

      if (!(await getFile('data/recipes.json'))) {
        await putFile('data/recipes.json', b64.enc(utf8.enc('[]')), 'Create recipes file');
      }

      rememberDevice();
      $('#s-token').value = $('#s-pass').value = $('#s-pass2').value = '';
      await start();
    } catch (ex) {
      token = null;
      cfg = null;
      err.textContent = ex.status === 404
        ? 'Repository not found, or the token has no access to it.'
        : ex.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Create my cookbook';
    }
  });

  $('#lock-btn').addEventListener('click', () => {
    if (confirm('Lock this device? You will need the password again.')) lockDevice();
  });

  document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab)));

  // Search
  $('#search').addEventListener('input', renderGallery);
  document.querySelectorAll('.chip').forEach((chip) =>
    chip.addEventListener('click', () => {
      searchMode = chip.dataset.mode;
      document.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', c === chip));
      renderGallery();
    })
  );

  // Detail dialog
  $('#close-detail').addEventListener('click', () => $('#detail').close());
  $('#detail').addEventListener('click', (e) => {
    if (e.target === $('#detail')) $('#detail').close(); // click on backdrop
  });

  $('#delete-btn').addEventListener('click', async () => {
    if (!current || !confirm(`Delete “${current.title}”?`)) return;
    const target = current;
    const btn = $('#delete-btn');
    btn.disabled = true;
    try {
      await commitRecipes((list) => list.filter((r) => r.id !== target.id), `Delete recipe: ${target.title}`);
      if (target.image) {
        const file = await getFile(target.image);
        if (file) await gh(contentsPath(target.image), {
          method: 'DELETE',
          body: JSON.stringify({ message: `Delete picture: ${target.title}`, sha: file.sha, branch: cfg.branch }),
        });
      }
      $('#detail').close();
      renderGallery();
    } catch (ex) {
      alert(`Could not delete: ${ex.message}`);
    } finally {
      btn.disabled = false;
    }
  });

  // Creation
  $('#f-image').addEventListener('change', (e) => {
    const file = e.target.files[0];
    const preview = $('#preview');
    if (!file) { preview.hidden = true; return; }
    preview.src = URL.createObjectURL(file);
    preview.hidden = false;
  });

  $('#create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#save-btn');
    const msg = $('#create-msg');
    const title = $('#f-title').value.trim();
    const ingredients = lines($('#f-ingredients').value, false);
    const steps = lines($('#f-steps').value, true);

    if (!title || !ingredients.length || !steps.length) {
      msg.textContent = 'Please fill in the title, the ingredients and the steps.';
      return;
    }

    btn.disabled = true;
    try {
      const slug = norm(title).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'recipe';
      const id = `${slug}-${Date.now().toString(36)}`;
      const recipe = { id, title, image: null, ingredients, steps, createdAt: new Date().toISOString() };

      const file = $('#f-image').files[0];
      if (file) {
        msg.textContent = 'Uploading picture…';
        const path = `images/${id}.jpg`;
        await putFile(path, await prepareImage(file), `Add picture: ${title}`);
        recipe.image = path;
      }

      msg.textContent = 'Saving recipe…';
      await commitRecipes((list) => [recipe, ...list], `Add recipe: ${title}`);

      $('#create-form').reset();
      $('#preview').hidden = true;
      msg.textContent = '';
      $('#search').value = '';
      showTab('gallery');
      renderGallery();
    } catch (ex) {
      msg.textContent = `Could not save: ${ex.message}`;
    } finally {
      btn.disabled = false;
    }
  });

  init();
})();
