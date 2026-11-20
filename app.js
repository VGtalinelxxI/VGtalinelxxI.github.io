(() => {
  'use strict';

  /* ────────────────────────────────────────────────────────────
     cookbook — static app hosted on GitHub Pages.

     data/recipes.json      → [{ id, title, image, ingredients:[{ingredientId, quantity}], steps:[], createdAt }]
     data/ingredients.json  → [{ id, name }]   (shared library, reused by every recipe)
     images/<id>.jpg        → recipe pictures
     config.json            → repo + GitHub token encrypted with your password

     Everything is committed through the GitHub API.
     The password is asked once per device, then remembered.
     ──────────────────────────────────────────────────────────── */

  const API = 'https://api.github.com';
  const LS_TOKEN = 'cookbook.token';
  const LS_CFG = 'cookbook.cfg';
  const LS_GROCERY = 'cookbook.grocery';
  const PBKDF2_ITERATIONS = 250000;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let cfg = null;               // { repo: "owner/name", branch: "main" }
  let token = null;
  let recipes = [];
  let ingredients = [];
  let ingMap = new Map();       // ingredient id → ingredient
  let recipesSha = null;
  let ingredientsSha = null;
  let remoteRecipesJson = '[]'; // what GitHub currently holds (to know what must be written)
  let remoteIngredientsJson = '[]';
  let searchMode = 'all';
  let current = null;           // recipe shown in the detail dialog
  let grocery = loadGrocery();  // { selected: [recipeId], checked: [ingredientId] }

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

  // Lower case, no accents, œ→oe: so "oeuf" finds "Œufs" and "creme" finds "Crème".
  const norm = (s) =>
    s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/œ/g, 'oe').replace(/æ/g, 'ae');
  const slug = (s) => norm(s).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  const clean = (s) => s.replace(/\s+/g, ' ').trim();
  const clone = (v) => JSON.parse(JSON.stringify(v));
  const encodeJson = (v) => b64.enc(utf8.enc(JSON.stringify(v, null, 2)));

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
      let message = body.message || res.statusText;
      if (res.status === 403 && /not accessible/i.test(message)) {
        message = 'The token is missing a permission. Edit it on GitHub: Repository access must include this repo, ' +
          'and Repository permissions → Contents must be "Read and write". (GitHub said: ' + message + ')';
      }
      const err = new Error(message);
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

  /* ───────── ingredients library ───────── */

  const ingName = (entry) => (ingMap.get(entry.ingredientId) || {}).name || entry.ingredientId || '';

  // Finds an ingredient by name (ignoring case/accents) or creates it in `list`.
  function getOrCreateIngredient(list, rawName) {
    const name = clean(rawName);
    const key = norm(name);
    let ing = list.find((i) => norm(i.name) === key);
    if (!ing) {
      const base = slug(name) || 'ingredient';
      let id = base;
      let n = 2;
      while (list.some((i) => i.id === id)) id = `${base}-${n++}`;
      ing = { id, name };
      list.push(ing);
    }
    return ing;
  }

  // "250 g de farine" → { quantity: "250 g", name: "Farine" }   (only used for old recipes)
  const LEGACY_RE = /^(\d+(?:[.,/]\d+)?(?:\s*(?:kg|mg|g|dl|cl|ml|l|oz|lbs?|tsp|tbsp|cups?|pinch(?:es)?))?)\s+(?:(?:of|de|du|des)\s+|d')?(.+)$/i;

  function parseLegacy(text) {
    const t = clean(text);
    const m = t.match(LEGACY_RE);
    const name = m ? m[2] : t;
    return { name: name.charAt(0).toUpperCase() + name.slice(1), quantity: m ? m[1] : '' };
  }

  // Recipes saved by the first version stored ingredients as plain text lines.
  // They are converted in memory on load and written back the next time anything is saved.
  function migrate(recipeList, ingredientList) {
    for (const r of recipeList) {
      if (!Array.isArray(r.ingredients)) r.ingredients = [];
      if (!Array.isArray(r.steps)) r.steps = [];
      r.ingredients = r.ingredients.map((entry) => {
        if (typeof entry !== 'string') return entry;
        const { name, quantity } = parseLegacy(entry);
        return { ingredientId: getOrCreateIngredient(ingredientList, name).id, quantity };
      });
    }
  }

  /* ───────── data storage ───────── */

  function setData(r, i) {
    recipes = r;
    ingredients = i;
    ingMap = new Map(i.map((x) => [x.id, x]));
  }

  async function loadData() {
    const [rf, inf] = await Promise.all([getFile('data/recipes.json'), getFile('data/ingredients.json')]);
    const parse = (f) => {
      if (!f) return [];
      const value = JSON.parse(utf8.dec(b64.dec(f.content)) || '[]');
      return Array.isArray(value) ? value : [];
    };
    const r = parse(rf);
    const i = parse(inf);
    recipesSha = rf ? rf.sha : null;
    ingredientsSha = inf ? inf.sha : null;
    remoteRecipesJson = JSON.stringify(r);
    remoteIngredientsJson = JSON.stringify(i);
    migrate(r, i);
    setData(r, i);
  }

  // Reloads the latest data, applies `mutate`, writes whatever changed. Retries on conflict.
  // Ingredients are written first, so a failure can only leave unused ingredients, never a broken recipe.
  async function commitData(mutate, message) {
    for (let attempt = 0; attempt < 3; attempt++) {
      await loadData();
      const d = { recipes: clone(recipes), ingredients: clone(ingredients) };
      mutate(d);
      const rJson = JSON.stringify(d.recipes);
      const iJson = JSON.stringify(d.ingredients);
      try {
        if (iJson !== remoteIngredientsJson) {
          const res = await putFile('data/ingredients.json', encodeJson(d.ingredients), message, ingredientsSha);
          ingredientsSha = res.content.sha;
          remoteIngredientsJson = iJson;
        }
        if (rJson !== remoteRecipesJson) {
          const res = await putFile('data/recipes.json', encodeJson(d.recipes), message, recipesSha);
          recipesSha = res.content.sha;
          remoteRecipesJson = rJson;
        }
        setData(d.recipes, d.ingredients);
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

  function loadImage(img, recipe) {
    img.loading = 'lazy';
    img.alt = recipe.title;
    // Falls back to the GitHub Pages copy if raw.githubusercontent is unavailable.
    img.onerror = () => {
      img.onerror = null;
      img.src = recipe.image;
    };
    img.src = `https://raw.githubusercontent.com/${cfg.repo}/${cfg.branch}/${recipe.image}`;
  }

  function thumbFor(recipe, className) {
    if (recipe.image) {
      const img = el('img', { className });
      loadImage(img, recipe);
      return img;
    }
    return el('div', { className: `${className} empty` }, '🍽️');
  }

  /* ───────── gallery & search ───────── */

  function matches(recipe, terms) {
    const title = norm(recipe.title);
    const names = recipe.ingredients.map((e) => norm(ingName(e)));
    return terms.every((t) => {
      const inTitle = title.includes(t);
      const inIngredients = names.some((n) => n.includes(t));
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
      const n = r.ingredients.length;
      const card = el(
        'button',
        { className: 'card', type: 'button' },
        thumbFor(r, 'thumb'),
        el('div', { className: 'info' },
          el('div', { className: 'name' }, r.title),
          el('div', { className: 'meta' }, n ? `${n} ingredient${n > 1 ? 's' : ''}` : ''))
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

    $('#d-ing-sec').hidden = !r.ingredients.length;
    $('#d-ingredients').replaceChildren(
      ...r.ingredients.map((e) =>
        el('li', {}, ...(e.quantity ? [el('span', { className: 'qty' }, e.quantity), ' '] : []), ingName(e)))
    );

    $('#d-steps-sec').hidden = !r.steps.length;
    $('#d-steps').replaceChildren(...r.steps.map((s) => el('li', {}, s)));

    updateDetailGrocery();
    $('#detail').showModal();
    $('#detail').scrollTop = 0;
  }

  function updateDetailGrocery() {
    if (!current) return;
    $('#d-grocery').textContent = grocery.selected.includes(current.id)
      ? '✓ In grocery list (tap to remove)'
      : '🛒 Add to grocery list';
  }

  /* ───────── create form: ingredient rows ───────── */

  function addIngredientRow(name = '', quantity = '', focus = false) {
    const nameInput = el('input', { className: 'ing-name', placeholder: 'Ingredient', value: name });
    nameInput.setAttribute('list', 'ing-list');
    nameInput.setAttribute('aria-label', 'Ingredient');
    nameInput.setAttribute('autocomplete', 'off');
    const tag = el('span', { className: 'tag', hidden: true }, 'new');
    const qty = el('input', { className: 'ing-qty', placeholder: 'Quantity', value: quantity });
    qty.setAttribute('aria-label', 'Quantity');
    qty.setAttribute('autocomplete', 'off');
    const remove = el('button', { type: 'button', className: 'icon-btn', title: 'Remove', textContent: '✕' });
    remove.setAttribute('aria-label', 'Remove ingredient');

    const refreshTag = () => {
      const v = clean(nameInput.value);
      tag.hidden = !v || ingredients.some((i) => norm(i.name) === norm(v));
    };
    nameInput.addEventListener('input', refreshTag);
    nameInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); qty.focus(); }
    });
    qty.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); addIngredientRow('', '', true); }
    });

    const row = el('div', { className: 'ing-row' }, el('div', { className: 'ing-name-wrap' }, nameInput, tag), qty, remove);
    remove.addEventListener('click', () => {
      row.remove();
      if (!$$('#ing-rows .ing-row').length) addIngredientRow();
    });
    $('#ing-rows').append(row);
    refreshTag();
    if (focus) nameInput.focus();
  }

  function readIngredientRows() {
    return $$('#ing-rows .ing-row')
      .map((row) => ({
        name: clean(row.querySelector('.ing-name').value),
        quantity: clean(row.querySelector('.ing-qty').value),
      }))
      .filter((x) => x.name);
  }

  function resetCreateForm() {
    $('#create-form').reset();
    $('#ing-rows').replaceChildren();
    addIngredientRow();
    $('#preview').hidden = true;
  }

  function updateDatalist() {
    const sorted = ingredients.slice().sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
    $('#ing-list').replaceChildren(...sorted.map((i) => el('option', { value: i.name })));
  }

  /* ───────── grocery mode ───────── */

  function loadGrocery() {
    try {
      const g = JSON.parse(localStorage.getItem(LS_GROCERY) || '{}');
      return {
        selected: Array.isArray(g.selected) ? g.selected : [],
        checked: Array.isArray(g.checked) ? g.checked : [],
      };
    } catch (_) {
      return { selected: [], checked: [] };
    }
  }

  function saveGrocery() {
    try { localStorage.setItem(LS_GROCERY, JSON.stringify(grocery)); } catch (_) { /* private mode */ }
  }

  function pruneGrocery() {
    if (!recipes.length && !grocery.selected.length) return;
    const ids = new Set(recipes.map((r) => r.id));
    const kept = grocery.selected.filter((id) => ids.has(id));
    if (kept.length !== grocery.selected.length) {
      grocery.selected = kept;
      saveGrocery();
    }
  }

  function toggleSelected(id, on) {
    const set = new Set(grocery.selected);
    on ? set.add(id) : set.delete(id);
    grocery.selected = [...set];
    saveGrocery();
    renderGrocery();
    updateDetailGrocery();
  }

  function toggleChecked(id, on) {
    const set = new Set(grocery.checked);
    on ? set.add(id) : set.delete(id);
    grocery.checked = [...set];
    saveGrocery();
    renderGrocery();
  }

  function renderGrocery() {
    pruneGrocery();
    const selected = new Set(grocery.selected);
    const checked = new Set(grocery.checked);

    // 1. Recipe picker
    const terms = norm($('#g-filter').value).split(/\s+/).filter(Boolean);
    const picker = $('#g-recipes');
    picker.replaceChildren();
    for (const r of recipes) {
      if (!terms.every((t) => norm(r.title).includes(t))) continue;
      const cb = el('input', { type: 'checkbox', checked: selected.has(r.id) });
      cb.addEventListener('change', () => toggleSelected(r.id, cb.checked));
      const n = r.ingredients.length;
      picker.append(
        el('label', { className: 'pick' },
          cb,
          thumbFor(r, 'pick-thumb'),
          el('span', { className: 'pick-title' }, r.title),
          el('small', { className: 'muted' }, n ? `${n} ingr.` : 'no ingredients'))
      );
    }
    $('#g-count').textContent = selected.size ? `(${selected.size} selected)` : '';

    // 2. Build the list: one entry per ingredient, with every recipe that needs it
    const items = new Map();
    const withoutIngredients = [];
    for (const r of recipes) {
      if (!selected.has(r.id)) continue;
      if (!r.ingredients.length) withoutIngredients.push(r.title);
      for (const e of r.ingredients) {
        let item = items.get(e.ingredientId);
        if (!item) items.set(e.ingredientId, (item = { id: e.ingredientId, name: ingName(e), uses: [] }));
        item.uses.push({ recipe: r.title, quantity: e.quantity || '' });
      }
    }

    const sorted = [...items.values()].sort((a, b) =>
      (checked.has(a.id) - checked.has(b.id)) || a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));

    const list = $('#g-list');
    list.replaceChildren();
    for (const item of sorted) {
      const done = checked.has(item.id);
      const cb = el('input', { type: 'checkbox', checked: done });
      cb.addEventListener('change', () => toggleChecked(item.id, cb.checked));
      list.append(
        el('li', { className: 'g-item' + (done ? ' done' : '') },
          el('label', { className: 'g-main' }, cb, el('span', { className: 'g-name' }, item.name)),
          el('ul', { className: 'g-uses' },
            ...item.uses.map((u) =>
              el('li', {}, el('span', { className: 'g-recipe' }, u.recipe),
                u.quantity ? el('span', { className: 'g-qty' }, ` — ${u.quantity}`) : ''))))
      );
    }

    // 3. Messages
    const doneCount = sorted.filter((i) => checked.has(i.id)).length;
    $('#g-summary').textContent = sorted.length ? `${sorted.length} item${sorted.length > 1 ? 's' : ''} · ${doneCount} checked` : '';

    let msg = '';
    if (!recipes.length) msg = 'Add some recipes first.';
    else if (!selected.size) msg = 'Select recipes above to build your shopping list.';
    else if (!sorted.length) msg = 'The selected recipes have no ingredients yet.';
    if (withoutIngredients.length && sorted.length) {
      msg = `${withoutIngredients.join(', ')} ${withoutIngredients.length > 1 ? 'have' : 'has'} no ingredients yet.`;
    }
    $('#g-empty').textContent = msg;
  }

  /* ───────── tabs & screens ───────── */

  function showTab(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $('#tab-gallery').hidden = name !== 'gallery';
    $('#tab-create').hidden = name !== 'create';
    $('#tab-grocery').hidden = name !== 'grocery';
    if (name === 'grocery') renderGrocery();
  }

  function show(which) {
    $('#lock').hidden = which !== 'lock';
    $('#setup').hidden = which !== 'setup';
    $('#app').hidden = which !== 'app';
  }

  function refreshAll() {
    renderGallery();
    updateDatalist();
    renderGrocery();
  }

  async function start() {
    show('app');
    showTab('gallery');
    $('#status').textContent = 'Loading recipes…';
    try {
      await loadData();
      refreshAll();
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
      await putFile('config.json', encodeJson(config), 'Set up cookbook', existing && existing.sha);

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

  $$('.tab').forEach((t) => t.addEventListener('click', () => showTab(t.dataset.tab)));

  // Search
  $('#search').addEventListener('input', renderGallery);
  $$('.chip').forEach((chip) =>
    chip.addEventListener('click', () => {
      searchMode = chip.dataset.mode;
      $$('.chip').forEach((c) => c.classList.toggle('active', c === chip));
      renderGallery();
    })
  );

  // Detail dialog
  $('#close-detail').addEventListener('click', () => $('#detail').close());
  $('#detail').addEventListener('click', (e) => {
    if (e.target === $('#detail')) $('#detail').close(); // click on backdrop
  });
  $('#d-grocery').addEventListener('click', () => {
    if (current) toggleSelected(current.id, !grocery.selected.includes(current.id));
  });

  $('#delete-btn').addEventListener('click', async () => {
    if (!current || !confirm(`Delete “${current.title}”?`)) return;
    const target = current;
    const btn = $('#delete-btn');
    btn.disabled = true;
    try {
      await commitData((d) => { d.recipes = d.recipes.filter((r) => r.id !== target.id); }, `Delete recipe: ${target.title}`);
      if (target.image) {
        const file = await getFile(target.image);
        if (file) await gh(contentsPath(target.image), {
          method: 'DELETE',
          body: JSON.stringify({ message: `Delete picture: ${target.title}`, sha: file.sha, branch: cfg.branch }),
        });
      }
      $('#detail').close();
      current = null;
      refreshAll();
    } catch (ex) {
      alert(`Could not delete: ${ex.message}`);
    } finally {
      btn.disabled = false;
    }
  });

  // Grocery
  $('#g-filter').addEventListener('input', renderGrocery);
  $('#g-uncheck').addEventListener('click', () => {
    grocery.checked = [];
    saveGrocery();
    renderGrocery();
  });
  $('#g-clear').addEventListener('click', () => {
    grocery = { selected: [], checked: [] };
    saveGrocery();
    renderGrocery();
  });

  // Creation
  $('#add-ing').addEventListener('click', () => addIngredientRow('', '', true));

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
    const title = clean($('#f-title').value);

    if (!title) {
      msg.textContent = 'Please enter a title.';
      return;
    }
    const entries = readIngredientRows();
    const steps = lines($('#f-steps').value, true);

    btn.disabled = true;
    try {
      const id = `${slug(title).slice(0, 40) || 'recipe'}-${Date.now().toString(36)}`;
      const recipe = { id, title, image: null, ingredients: [], steps, createdAt: new Date().toISOString() };

      const file = $('#f-image').files[0];
      if (file) {
        msg.textContent = 'Uploading picture…';
        const path = `images/${id}.jpg`;
        await putFile(path, await prepareImage(file), `Add picture: ${title}`);
        recipe.image = path;
      }

      msg.textContent = 'Saving recipe…';
      await commitData((d) => {
        recipe.ingredients = entries.map(({ name, quantity }) => ({
          ingredientId: getOrCreateIngredient(d.ingredients, name).id,
          quantity,
        }));
        d.recipes.unshift(recipe);
      }, `Add recipe: ${title}`);

      resetCreateForm();
      msg.textContent = '';
      $('#search').value = '';
      showTab('gallery');
      refreshAll();
    } catch (ex) {
      msg.textContent = `Could not save: ${ex.message}`;
    } finally {
      btn.disabled = false;
    }
  });

  addIngredientRow();
  init();
})();
