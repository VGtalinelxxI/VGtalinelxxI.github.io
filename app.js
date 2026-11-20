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
  const LS_PANTRY = 'cookbook.pantry';
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
  let pantry = loadPantry();    // { have: [ingredientId], maxMissing: 2 }

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
      return await gh(`${contentsPath(path)}?ref=${encodeURIComponent(cfg.branch)}&t=${Date.now()}`);
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
      await new Promise((resolve, reject) => {
        img.onload = resolve;
        img.onerror = () => reject(new Error('This picture format cannot be read by the browser. Try a JPEG or PNG.'));
        img.src = url;
      });
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
    if (bmp.close) bmp.close();
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
    if (!blob) {
      // Some phones return null for large canvases: fall back to a data URL.
      return canvas.toDataURL('image/jpeg', quality).split(',')[1];
    }
    return b64.enc(await readBlob(blob));
  }

  // Blob.arrayBuffer() is missing on older iOS versions.
  function readBlob(blob) {
    if (blob.arrayBuffer) return blob.arrayBuffer();
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsArrayBuffer(blob);
    });
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

  // Ingredient names whose normalised form contains every typed word; prefix matches first.
  function suggestIngredients(text, exclude = new Set(), limit = 6) {
    const q = norm(clean(text));
    if (!q) return [];
    const words = q.split(' ');
    return ingredients
      .map((i) => ({ i, n: norm(i.name) }))
      .filter(({ i, n }) => !exclude.has(i.id) && words.every((w) => n.includes(w)))
      .sort((a, b) => (b.n.startsWith(q) - a.n.startsWith(q)) || a.n.localeCompare(b.n))
      .slice(0, limit)
      .map(({ i }) => i);
  }

  // A small dropdown under an input. The native <datalist> is unreliable on phones
  // (several mobile browsers show it as an empty white box), so it is not used.
  function attachSuggest(input, onPick, { exclude = () => new Set(), showWhenEmpty = false } = {}) {
    const box = el('ul', { className: 'suggest', hidden: true });
    box.setAttribute('role', 'listbox');
    let items = [];
    let active = -1;

    const close = () => { box.hidden = true; active = -1; };
    const paint = () => [...box.children].forEach((li, k) => li.classList.toggle('active', k === active));
    const open = () => {
      items = suggestIngredients(input.value, exclude());
      const exact = items.length === 1 && norm(items[0].name) === norm(clean(input.value));
      if (!items.length || exact || (!showWhenEmpty && !clean(input.value))) return close();
      box.replaceChildren(...items.map((i) => {
        const li = el('li', { textContent: i.name });
        li.setAttribute('role', 'option');
        // pointerdown + preventDefault keeps the focus in the input (no keyboard flicker on phones)
        li.addEventListener('pointerdown', (e) => e.preventDefault());
        li.addEventListener('mousedown', (e) => e.preventDefault());
        li.addEventListener('click', () => { close(); onPick(i); });
        return li;
      }));
      active = -1;
      box.hidden = false;
    };

    input.addEventListener('input', open);
    input.addEventListener('focus', open);
    input.addEventListener('blur', () => setTimeout(close, 150));
    input.addEventListener('keydown', (e) => {
      if (box.hidden) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        const n = items.length;
        active = (active + (e.key === 'ArrowDown' ? 1 : -1) + n) % n;
        paint();
      } else if (e.key === 'Enter' && active >= 0) {
        e.preventDefault();
        e.stopImmediatePropagation();
        const pick = items[active];
        close();
        onPick(pick);
      } else if (e.key === 'Escape') {
        close();
      }
    });
    return box;
  }

  function addIngredientRow(name = '', quantity = '', focus = false) {
    const nameInput = el('input', { type: 'text', className: 'ing-name', placeholder: 'Ingredient', value: name });
    nameInput.setAttribute('aria-label', 'Ingredient');
    nameInput.setAttribute('autocomplete', 'off');
    nameInput.setAttribute('autocapitalize', 'sentences');
    nameInput.setAttribute('enterkeyhint', 'next');
    const tag = el('span', { className: 'tag', hidden: true }, 'new');
    const qty = el('input', { type: 'text', className: 'ing-qty', placeholder: 'Qty', value: quantity });
    qty.setAttribute('aria-label', 'Quantity');
    qty.setAttribute('autocomplete', 'off');
    qty.setAttribute('enterkeyhint', 'next');
    const remove = el('button', { type: 'button', className: 'icon-btn', title: 'Remove', textContent: '✕' });
    remove.setAttribute('aria-label', 'Remove ingredient');

    const refreshTag = () => {
      const v = clean(nameInput.value);
      tag.hidden = !v || ingredients.some((i) => norm(i.name) === norm(v));
    };
    const box = attachSuggest(nameInput, (ing) => {
      nameInput.value = ing.name;
      refreshTag();
      qty.focus();
    });
    nameInput.addEventListener('input', refreshTag);
    nameInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); qty.focus(); }
    });
    qty.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); addIngredientRow('', '', true); }
    });

    const row = el('div', { className: 'ing-row' }, el('div', { className: 'ing-name-wrap' }, nameInput, tag, box), qty, remove);
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

    lastGroceryItems = sorted;
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
    $('#g-export').hidden = !sorted.length;
    $('#g-mark-have').hidden = !sorted.length || !pantry.have.length;
  }

  /* ───────── grocery export ───────── */

  let lastGroceryItems = [];

  function groceryText() {
    const checked = new Set(grocery.checked);
    const withChecked = $('#g-exp-checked').checked;
    const withRecipes = $('#g-exp-recipes').checked;
    const items = lastGroceryItems.filter((i) => withChecked || !checked.has(i.id));
    const date = new Date().toLocaleDateString();
    const out = [`🛒 Shopping list — ${date}`, ''];
    for (const item of items) {
      out.push(`${checked.has(item.id) ? '☑' : '☐'} ${item.name}`);
      if (withRecipes) {
        for (const u of item.uses) out.push(`    ${u.recipe}${u.quantity ? ` — ${u.quantity}` : ''}`);
      }
    }
    const done = items.filter((i) => checked.has(i.id)).length;
    if (!items.length) out.push('Everything is already checked. ✔');
    else out.push('', `${items.length} item${items.length > 1 ? 's' : ''} · ${done} checked`);
    return out.join('\n');
  }

  // A link that rebuilds the same list (same recipes, same ticks) on another device.
  function groceryLink() {
    const data = JSON.stringify({ s: grocery.selected, c: grocery.checked });
    const code = b64.enc(utf8.enc(data)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `${location.origin}${location.pathname}#list=${code}`;
  }

  // Opens a list received through “Link with ticks”.
  function importSharedList() {
    const shared = readListFromHash();
    if (!shared) return;
    history.replaceState(null, '', location.pathname + location.search);
    const same = JSON.stringify(shared) === JSON.stringify(grocery);
    if (!same && grocery.selected.length && !confirm('Replace your current grocery list with the shared one?')) return;
    grocery = shared;
    saveGrocery();
    renderGrocery();
    showTab('grocery');
  }
  window.addEventListener('hashchange', () => { if (token && recipes.length) importSharedList(); });

  function readListFromHash() {
    const m = location.hash.match(/^#list=([A-Za-z0-9_-]+)/);
    if (!m) return null;
    try {
      let code = m[1].replace(/-/g, '+').replace(/_/g, '/');
      while (code.length % 4) code += '=';
      const d = JSON.parse(utf8.dec(b64.dec(code)));
      return { selected: Array.isArray(d.s) ? d.s : [], checked: Array.isArray(d.c) ? d.c : [] };
    } catch (_) {
      return null;
    }
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const ta = el('textarea', { value: text });
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.append(ta);
      ta.select();
      ta.setSelectionRange(0, text.length);
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { /* ignore */ }
      ta.remove();
      return ok;
    }
  }

  function flash(msg) {
    const n = $('#g-exp-msg');
    n.textContent = msg;
    clearTimeout(flash.t);
    flash.t = setTimeout(() => { n.textContent = ''; }, 3000);
  }

  async function shareOrCopy(payload, copied) {
    if (navigator.share) {
      try {
        await navigator.share(payload);
        return;
      } catch (e) {
        if (e && e.name === 'AbortError') return; // user closed the share sheet
      }
    }
    flash((await copyText(payload.url || payload.text)) ? copied : 'Could not copy. Use “Download” instead.');
  }

  function downloadText(text, filename) {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const a = el('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ───────── cook mode: what can I make with what I have? ───────── */

  function loadPantry() {
    try {
      const p = JSON.parse(localStorage.getItem(LS_PANTRY) || '{}');
      return {
        have: Array.isArray(p.have) ? p.have : [],
        maxMissing: Number.isInteger(p.maxMissing) ? p.maxMissing : 2,
      };
    } catch (_) {
      return { have: [], maxMissing: 2 };
    }
  }

  function savePantry() {
    try { localStorage.setItem(LS_PANTRY, JSON.stringify(pantry)); } catch (_) { /* private mode */ }
  }

  function toggleHave(id, on) {
    const set = new Set(pantry.have);
    on ? set.add(id) : set.delete(id);
    pantry.have = [...set];
    savePantry();
    renderCook();
  }

  function cookChip(ing, on) {
    const b = el('button', { type: 'button', className: 'ing-chip' + (on ? ' on' : ''), textContent: (on ? '✓ ' : '') + ing.name });
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
    b.addEventListener('click', () => toggleHave(ing.id, !on));
    return b;
  }

  // Ticks, in the grocery list, every ingredient the user already has.
  function markHaveInGrocery() {
    const set = new Set(grocery.checked);
    pantry.have.forEach((id) => set.add(id));
    grocery.checked = [...set];
    saveGrocery();
  }

  function renderCook() {
    if (!$('#tab-cook')) return;
    // Forget ingredients that no longer exist
    if (ingredients.length) {
      const kept = pantry.have.filter((id) => ingMap.has(id));
      if (kept.length !== pantry.have.length) { pantry.have = kept; savePantry(); }
    }
    const have = new Set(pantry.have);
    const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });

    // 1. Selected ingredients
    const sel = $('#c-selected');
    const selected = pantry.have.map((id) => ingMap.get(id)).filter(Boolean).sort(byName);
    sel.replaceChildren(...selected.map((i) => cookChip(i, true)));
    $('#c-count').textContent = selected.length ? `(${selected.length})` : '';
    $('#c-clear').hidden = !selected.length;

    // 2. Library, filtered, only ingredients used by at least one recipe (most used first)
    const used = new Map();
    for (const r of recipes) for (const e of new Set(r.ingredients.map((x) => x.ingredientId))) used.set(e, (used.get(e) || 0) + 1);
    const terms = norm($('#c-filter').value).split(/\s+/).filter(Boolean);
    const pool = ingredients
      .filter((i) => used.has(i.id) && !have.has(i.id))
      .filter((i) => terms.every((t) => norm(i.name).includes(t)))
      .sort((a, b) => (terms.length ? 0 : used.get(b.id) - used.get(a.id)) || byName(a, b));
    $('#c-library').replaceChildren(...pool.map((i) => cookChip(i, false)));
    $('#c-library-empty').textContent = !ingredients.length
      ? 'Your recipes have no ingredients yet.'
      : !pool.length && terms.length ? 'No ingredient matches.' : '';

    // 3. Results
    $('#c-max').value = String(pantry.maxMissing);
    const can = [];
    const almost = [];
    let noIng = 0;
    for (const r of recipes) {
      const ids = [...new Set(r.ingredients.map((e) => e.ingredientId))];
      if (!ids.length) { noIng++; continue; }
      const missing = ids.filter((id) => !have.has(id));
      const owned = ids.length - missing.length;
      if (!missing.length) can.push({ r, missing, owned, total: ids.length });
      else if (owned > 0 && missing.length <= pantry.maxMissing) almost.push({ r, missing, owned, total: ids.length });
    }
    can.sort((a, b) => b.total - a.total || a.r.title.localeCompare(b.r.title));
    almost.sort((a, b) => a.missing.length - b.missing.length || b.owned / b.total - a.owned / a.total || a.r.title.localeCompare(b.r.title));

    const resultCard = ({ r, missing, owned, total }) => {
      const open = el('button', { type: 'button', className: 'c-open' },
        thumbFor(r, 'pick-thumb'),
        el('span', { className: 'c-info' },
          el('span', { className: 'pick-title' }, r.title),
          el('small', { className: 'muted' }, `${owned}/${total} ingredients`)));
      open.addEventListener('click', () => openDetail(r));
      const inList = grocery.selected.includes(r.id);
      const add = el('button', { type: 'button', className: 'secondary small', textContent: inList ? '✓ In list' : '🛒 Add' });
      add.title = 'Add this recipe to the grocery list, with what you have already ticked';
      add.addEventListener('click', () => {
        if (!grocery.selected.includes(r.id)) grocery.selected = [...grocery.selected, r.id];
        markHaveInGrocery();
        renderGrocery();
        renderCook();
        updateDetailGrocery();
      });
      const card = el('li', { className: 'c-card' }, el('div', { className: 'c-row' }, open, add));
      if (missing.length) {
        card.append(el('div', { className: 'c-missing' },
          el('span', { className: 'muted' }, 'Missing: '),
          ...missing.map((id) => {
            const name = (ingMap.get(id) || {}).name || id;
            const q = r.ingredients.find((e) => e.ingredientId === id);
            const chip = el('button', { type: 'button', className: 'miss-chip', textContent: name + (q && q.quantity ? ` (${q.quantity})` : '') });
            chip.title = 'I have it';
            chip.addEventListener('click', () => toggleHave(id, true));
            return chip;
          })));
      }
      return card;
    };

    $('#c-can').replaceChildren(...can.map(resultCard));
    $('#c-almost').replaceChildren(...almost.map(resultCard));
    $('#c-can-title').textContent = `✅ You can make (${can.length})`;
    $('#c-almost-title').textContent = `🟡 Almost (${almost.length})`;
    $('#c-can-sec').hidden = !selected.length;
    $('#c-almost-sec').hidden = !selected.length;
    $('#c-can-empty').textContent = can.length ? '' : 'Nothing complete yet. Add more ingredients.';
    $('#c-almost-empty').textContent = almost.length ? '' : `No recipe missing ${pantry.maxMissing > 1 ? `${pantry.maxMissing} ingredients or fewer` : 'only one ingredient'}.`;
    $('#c-hint').textContent = !recipes.length
      ? 'Add some recipes first.'
      : !selected.length
        ? 'Tap the ingredients you have. Recipes you can make appear below.'
        : noIng ? `${noIng} recipe${noIng > 1 ? 's' : ''} without ingredients ${noIng > 1 ? 'are' : 'is'} not taken into account.` : '';
  }

  /* ───────── tabs & screens ───────── */

  function showTab(name) {
    $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
    $('#tab-gallery').hidden = name !== 'gallery';
    $('#tab-create').hidden = name !== 'create';
    $('#tab-grocery').hidden = name !== 'grocery';
    $('#tab-cook').hidden = name !== 'cook';
    if (name === 'grocery') renderGrocery();
    if (name === 'cook') renderCook();
    window.scrollTo(0, 0);
  }

  function show(which) {
    $('#lock').hidden = which !== 'lock';
    $('#setup').hidden = which !== 'setup';
    $('#app').hidden = which !== 'app';
  }

  function refreshAll() {
    renderGallery();
    renderGrocery();
    renderCook();
  }

  async function start() {
    show('app');
    showTab('gallery');
    $('#status').textContent = 'Loading recipes…';
    try {
      await loadData();
      refreshAll();
      importSharedList();
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

  $('#g-mark-have').addEventListener('click', () => {
    markHaveInGrocery();
    renderGrocery();
  });

  // Grocery export
  $('#g-share').addEventListener('click', () => shareOrCopy({ title: 'Shopping list', text: groceryText() }, 'List copied to the clipboard.'));
  $('#g-copy').addEventListener('click', async () =>
    flash((await copyText(groceryText())) ? 'List copied to the clipboard.' : 'Could not copy. Use “Download” instead.'));
  $('#g-download').addEventListener('click', () =>
    downloadText(groceryText(), `shopping-list-${new Date().toISOString().slice(0, 10)}.txt`));
  $('#g-print').addEventListener('click', () => window.print());
  $('#g-link').addEventListener('click', () =>
    shareOrCopy({ title: 'Shopping list', url: groceryLink() }, 'Link copied. Open it on another device to get the same list.'));

  // Cook mode
  $('#c-filter').addEventListener('input', renderCook);
  $('#c-filter').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const first = suggestIngredients($('#c-filter').value, new Set(pantry.have), 1)[0];
    if (first) {
      $('#c-filter').value = '';
      toggleHave(first.id, true);
    }
  });
  $('#c-max').addEventListener('change', () => {
    pantry.maxMissing = parseInt($('#c-max').value, 10) || 1;
    savePantry();
    renderCook();
  });
  $('#c-clear').addEventListener('click', () => {
    pantry.have = [];
    savePantry();
    renderCook();
  });

  // On phones, hide the bottom tab bar while typing so it never covers a field or the Save button.
  const isField = (t) => t && t.matches && t.matches('input:not([type="checkbox"]):not([type="file"]), textarea, select');
  document.addEventListener('focusin', (e) => { if (isField(e.target)) document.body.classList.add('typing'); });
  document.addEventListener('focusout', (e) => {
    if (isField(e.target)) setTimeout(() => { if (!isField(document.activeElement)) document.body.classList.remove('typing'); }, 100);
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

    const say = (text, isError) => {
      msg.textContent = text;
      msg.classList.toggle('error', !!isError);
      msg.scrollIntoView({ block: 'nearest' });
    };

    if (!title) {
      say('Please enter a title.', true);
      $('#f-title').focus();
      $('#f-title').scrollIntoView({ block: 'center' });
      return;
    }
    if (btn.disabled) return; // already saving
    if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
    const entries = readIngredientRows();
    const steps = lines($('#f-steps').value, true);

    btn.disabled = true;
    btn.textContent = 'Saving…';
    try {
      const id = `${slug(title).slice(0, 40) || 'recipe'}-${Date.now().toString(36)}`;
      const recipe = { id, title, image: null, ingredients: [], steps, createdAt: new Date().toISOString() };

      const file = $('#f-image').files[0];
      if (file) {
        say('Uploading picture…');
        const path = `images/${id}.jpg`;
        await putFile(path, await prepareImage(file), `Add picture: ${title}`);
        recipe.image = path;
      }

      say('Saving recipe…');
      await commitData((d) => {
        recipe.ingredients = entries.map(({ name, quantity }) => ({
          ingredientId: getOrCreateIngredient(d.ingredients, name).id,
          quantity,
        }));
        d.recipes.unshift(recipe);
      }, `Add recipe: ${title}`);

      resetCreateForm();
      say('');
      $('#search').value = '';
      showTab('gallery');
      refreshAll();
    } catch (ex) {
      say(`Could not save: ${ex.message}`, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Save recipe';
    }
  });

  // Older iOS (< 15.4) has no <dialog>: minimal fallback.
  const dlg = $('#detail');
  if (typeof dlg.showModal !== 'function') {
    dlg.classList.add('no-dialog');
    dlg.showModal = () => { dlg.setAttribute('open', ''); document.body.classList.add('modal-open'); };
    dlg.close = () => { dlg.removeAttribute('open'); document.body.classList.remove('modal-open'); };
  }

  addIngredientRow();
  init();
})();
