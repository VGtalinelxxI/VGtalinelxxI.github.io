(() => {
  'use strict';

  /* ────────────────────────────────────────────────────────────
     cookbook — static app hosted on GitHub Pages.

     data/recipes.json      → [{ id, title, image, categories:[categoryId],
                                 ingredients:[{ingredientId, quantity, note?, optional?}], steps:[], createdAt,
                                 updatedAt?, archived?, archivedAt? }]
     data/ingredients.json  → [{ id, name }]   (shared library, reused by every recipe)
     data/categories.json   → [{ id, name }]   (shared categories, a recipe can have several)
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
  const F_RECIPES = 'data/recipes.json';
  const F_INGREDIENTS = 'data/ingredients.json';
  const F_CATEGORIES = 'data/categories.json';
  const DEFAULT_CATEGORIES = ['Dessert', 'Pâtisserie', 'Entrée', 'Salade', 'Soupe', 'Plat', 'Végétarien'];
  const WORK_MAX = 2048;   // working copy used by the crop tool
  const OUT_MAX = 1280;    // size of the picture saved in the repo
  const OUT_QUALITY = 0.82;

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let cfg = null;               // { repo: "owner/name", branch: "main" }
  let token = null;
  let recipes = [];
  let ingredients = [];
  let ingMap = new Map();       // ingredient id → ingredient
  let categories = [];
  let catMap = new Map();       // category id → category
  let categoriesSha = null;
  let remoteCategoriesJson = null;
  let catFilter = new Set();    // gallery: selected category ids
  let formCats = [];            // form: selected category names
  let formExtraCats = [];       // form: new category names, created on save
  let pendingPicture = null;    // form: { work, base64, url, state } once a picture is chosen and cropped
  let recipesSha = null;
  let ingredientsSha = null;
  let remoteRecipesJson = '[]'; // what GitHub currently holds (to know what must be written)
  let remoteIngredientsJson = '[]';
  let searchMode = 'all';
  let current = null;           // recipe shown in the detail dialog
  let showArchived = false;     // gallery shows archived recipes instead of active ones
  let editing = null;           // { id, image } while a recipe is being edited
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

  // Archived recipes stay in the repo but are hidden from the gallery, grocery and cook modes.
  const activeRecipes = () => recipes.filter((r) => !r.archived);

  const ingName = (entry) => (ingMap.get(entry.ingredientId) || {}).name || entry.ingredientId || '';

  const catName = (id) => (catMap.get(id) || {}).name || id;
  const recipeCats = (r) => (r.categories || []).filter((id) => catMap.has(id));
  const byName = (a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });

  // "Orange (suprême)" typed in the name field → name "Orange", comment "suprême".
  function splitNote(name, note) {
    if (note) return { name, note };
    const m = name.match(/^(.+?)\s*\((.+)\)$/);
    return m ? { name: clean(m[1]), note: clean(m[2]) } : { name, note: '' };
  }

  // Quantity and comment of one ingredient line: "250 g (suprême)".
  const useDetail = (u) => [u.quantity, u.note && `(${u.note})`].filter(Boolean).join(' ');

  // Finds an entry by name (ignoring case/accents) or creates it in `list`. Used for ingredients and categories.
  function getOrCreateNamed(list, rawName, fallbackId) {
    const name = clean(rawName);
    const key = norm(name);
    let ing = list.find((i) => norm(i.name) === key);
    if (!ing) {
      const base = slug(name) || fallbackId;
      let id = base;
      let n = 2;
      while (list.some((i) => i.id === id)) id = `${base}-${n++}`;
      ing = { id, name };
      list.push(ing);
    }
    return ing;
  }
  const getOrCreateIngredient = (list, rawName) => getOrCreateNamed(list, rawName, 'ingredient');
  const getOrCreateCategory = (list, rawName) => getOrCreateNamed(list, rawName, 'category');

  const toEntry = (list, { name, quantity, note, optional }) => ({
    ingredientId: getOrCreateIngredient(list, name).id,
    quantity,
    ...(note ? { note } : {}),
    ...(optional ? { optional: true } : {}),
  });

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
      if (!Array.isArray(r.categories)) r.categories = [];
      r.ingredients = r.ingredients.map((entry) => {
        if (typeof entry !== 'string') return entry;
        const { name, quantity } = parseLegacy(entry);
        return { ingredientId: getOrCreateIngredient(ingredientList, name).id, quantity };
      });
    }
  }

  /* ───────── data storage ───────── */

  function setData(r, i, c) {
    recipes = r;
    ingredients = i;
    categories = c;
    ingMap = new Map(i.map((x) => [x.id, x]));
    catMap = new Map(c.map((x) => [x.id, x]));
  }

  async function loadData() {
    const [rf, inf, cf] = await Promise.all([getFile(F_RECIPES), getFile(F_INGREDIENTS), getFile(F_CATEGORIES)]);
    const parse = (f) => {
      if (!f) return [];
      const value = JSON.parse(utf8.dec(b64.dec(f.content)) || '[]');
      return Array.isArray(value) ? value : [];
    };
    const r = parse(rf);
    const i = parse(inf);
    // First run: the default categories are proposed, and written to the repo with the next save.
    const c = cf ? parse(cf) : DEFAULT_CATEGORIES.map((name) => ({ id: slug(name), name }));
    recipesSha = rf ? rf.sha : null;
    ingredientsSha = inf ? inf.sha : null;
    categoriesSha = cf ? cf.sha : null;
    remoteRecipesJson = JSON.stringify(r);
    remoteIngredientsJson = JSON.stringify(i);
    remoteCategoriesJson = cf ? JSON.stringify(c) : null;
    migrate(r, i);
    setData(r, i, c);
  }

  // Reloads the latest data, applies `mutate`, writes whatever changed. Retries on conflict.
  // Ingredients and categories are written first, so a failure can only leave unused entries, never a broken recipe.
  async function commitData(mutate, message) {
    for (let attempt = 0; attempt < 3; attempt++) {
      await loadData();
      const d = { recipes: clone(recipes), ingredients: clone(ingredients), categories: clone(categories) };
      mutate(d);
      const rJson = JSON.stringify(d.recipes);
      const iJson = JSON.stringify(d.ingredients);
      const cJson = JSON.stringify(d.categories);
      try {
        if (iJson !== remoteIngredientsJson) {
          const res = await putFile(F_INGREDIENTS, encodeJson(d.ingredients), message, ingredientsSha);
          ingredientsSha = res.content.sha;
          remoteIngredientsJson = iJson;
        }
        if (cJson !== remoteCategoriesJson) {
          const res = await putFile(F_CATEGORIES, encodeJson(d.categories), message, categoriesSha);
          categoriesSha = res.content.sha;
          remoteCategoriesJson = cJson;
        }
        if (rJson !== remoteRecipesJson) {
          const res = await putFile(F_RECIPES, encodeJson(d.recipes), message, recipesSha);
          recipesSha = res.content.sha;
          remoteRecipesJson = rJson;
        }
        setData(d.recipes, d.ingredients, d.categories);
        return;
      } catch (e) {
        if (e.status !== 409 && e.status !== 422) throw e;
      }
    }
    throw new Error('Could not save (conflicting changes). Please try again.');
  }

  /* ───────── pictures ───────── */

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

  function readDataUrl(blob) {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => reject(r.error);
      r.readAsDataURL(blob);
    });
  }

  // Real file type, read from the first bytes (the name and MIME type given by phones are often wrong or empty).
  async function sniff(blob) {
    const head = new Uint8Array(await readBlob(blob.slice(0, 64)));
    const ascii = String.fromCharCode(...head);
    if (head[0] === 0xff && head[1] === 0xd8) return 'jpeg';
    if (ascii.startsWith('\x89PNG')) return 'png';
    if (ascii.startsWith('GIF8')) return 'gif';
    if (ascii.startsWith('RIFF') && ascii.slice(8, 12) === 'WEBP') return 'webp';
    if (ascii.startsWith('BM')) return 'bmp';
    if (ascii.slice(4, 8) === 'ftyp') {
      if (/avi[fs]/.test(ascii.slice(8, 40))) return 'avif';
      if (/hei[cxms]|hev[cx]|mif1|msf1/.test(ascii.slice(8, 40))) return 'heic';
    }
    if (/<svg|<\?xml/.test(ascii)) return 'svg';
    return 'unknown';
  }

  function imgFromUrl(url) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => (img.naturalWidth ? resolve(img) : reject(new Error('empty')));
      img.onerror = () => reject(new Error('decode'));
      img.src = url;
    });
  }

  // Tries every decoder the browser has, from the fastest to the most tolerant.
  async function decodeBlob(blob) {
    const tries = [];
    if (window.createImageBitmap) {
      tries.push(() => createImageBitmap(blob, { imageOrientation: 'from-image' }));
      tries.push(() => createImageBitmap(blob));
    }
    tries.push(() => {
      const url = URL.createObjectURL(blob);
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      return imgFromUrl(url);
    });
    tries.push(async () => imgFromUrl(await readDataUrl(blob)));
    for (const attempt of tries) {
      try {
        const img = await attempt();
        if ((img.width || img.naturalWidth) > 0) return img;
      } catch (_) { /* next decoder */ }
    }
    return null;
  }

  // iPhone photos (HEIC) are converted in the browser by heic2any, loaded only when needed.
  let heicLib = null;
  function loadHeicLib() {
    if (window.heic2any) return Promise.resolve(window.heic2any);
    if (!heicLib) {
      heicLib = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = 'lib/heic2any.min.js';
        script.onload = () => (window.heic2any ? resolve(window.heic2any) : reject(new Error('HEIC converter unavailable.')));
        script.onerror = () => {
          heicLib = null;
          reject(new Error('Could not load the HEIC converter. Check the connection and try again.'));
        };
        document.head.append(script);
      });
    }
    return heicLib;
  }

  // Copies a decoded picture into a canvas of at most `max` px (white background for transparent PNG).
  function toCanvas(img, max) {
    const w = img.width || img.naturalWidth;
    const h = img.height || img.naturalHeight;
    const scale = Math.min(1, max / Math.max(w, h));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(w * scale));
    canvas.height = Math.max(1, Math.round(h * scale));
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    if (img.close) img.close();
    return canvas;
  }

  // Any picture file → canvas ready for the crop tool, or a clear explanation of the problem.
  async function loadPicture(file, onStatus = () => {}) {
    if (!file || !file.size) {
      throw new Error('This picture is empty. If it is stored in iCloud or Google Photos, open it once in the Photos app so it is downloaded to the phone, then try again.');
    }
    const kind = await sniff(file).catch(() => 'unknown');
    const name = file.name || '';
    let img = await decodeBlob(file);
    if (!img && (kind === 'heic' || /hei[cf]/i.test(file.type) || /\.hei[cf]$/i.test(name))) {
      onStatus('Converting the iPhone photo (HEIC)…');
      try {
        const lib = await loadHeicLib();
        let jpeg = await lib({ blob: file, toType: 'image/jpeg', quality: 0.92 });
        if (Array.isArray(jpeg)) jpeg = jpeg[0];
        img = await decodeBlob(jpeg);
      } catch (ex) {
        throw new Error(`Could not convert this HEIC photo (${ex.message || ex}). In the iPhone settings, Camera → Formats → “Most Compatible” saves new photos as JPEG.`);
      }
    }
    if (!img) {
      const what = kind !== 'unknown' ? kind.toUpperCase() : (file.type || name.split('.').pop() || 'unknown format');
      throw new Error(`This picture (${what}) cannot be read on this device. Take a screenshot of it, or share it as JPEG, then choose it again.`);
    }
    return toCanvas(img, WORK_MAX);
  }

  async function canvasToBase64(canvas) {
    const blob = await new Promise((resolve) => {
      try { canvas.toBlob(resolve, 'image/jpeg', OUT_QUALITY); } catch (_) { resolve(null); }
    });
    // Some phones return null for large canvases: fall back to a data URL.
    if (!blob) return canvas.toDataURL('image/jpeg', OUT_QUALITY).split(',')[1];
    return b64.enc(await readBlob(blob));
  }

  // Downloads a picture already saved in the repo (to crop it again).
  async function fetchPicture(path) {
    const urls = [`https://raw.githubusercontent.com/${cfg.repo}/${cfg.branch}/${path}`, path];
    for (const url of urls) {
      try {
        const res = await fetch(url, { cache: 'no-store' });
        if (res.ok) return await res.blob();
      } catch (_) { /* next url */ }
    }
    throw new Error('Could not download the current picture.');
  }

  /* ───────── crop tool ───────── */

  const RATIOS = { '4:3': 4 / 3, '1:1': 1, original: 0 };
  const crop = { src: null, rot: 0, ratioKey: '4:3', zoom: 1, cx: 0, cy: 0, done: null, pointers: new Map(), pinch: 0, raf: 0 };

  const rotSize = () => (crop.rot % 180 ? [crop.src.height, crop.src.width] : [crop.src.width, crop.src.height]);
  const cropRatio = () => {
    const [w, h] = rotSize();
    return RATIOS[crop.ratioKey] || w / h;
  };

  // Visible rectangle, in the coordinates of the rotated picture. Always stays inside the picture.
  function cropRect() {
    const [W, H] = rotSize();
    const ratio = cropRatio();
    let w;
    let h;
    if (W / H > ratio) { h = H / crop.zoom; w = h * ratio; } else { w = W / crop.zoom; h = w / ratio; }
    crop.cx = Math.min(Math.max(crop.cx, w / 2), W - w / 2);
    crop.cy = Math.min(Math.max(crop.cy, h / 2), H - h / 2);
    return { x: crop.cx - w / 2, y: crop.cy - h / 2, w, h };
  }

  function drawRotated(ctx) {
    const s = crop.src;
    if (crop.rot === 90) { ctx.translate(s.height, 0); ctx.rotate(Math.PI / 2); }
    else if (crop.rot === 180) { ctx.translate(s.width, s.height); ctx.rotate(Math.PI); }
    else if (crop.rot === 270) { ctx.translate(0, s.width); ctx.rotate(-Math.PI / 2); }
    ctx.drawImage(s, 0, 0);
  }

  function renderCrop() {
    if (!crop.src) return;
    const wrap = $('#crop-wrap');
    const stage = $('#crop-stage');
    const canvas = $('#crop-canvas');
    const ratio = cropRatio();
    const w = Math.max(60, Math.min(wrap.clientWidth - 24, (wrap.clientHeight - 24) * ratio));
    const h = w / ratio;
    stage.style.width = `${Math.round(w)}px`;
    stage.style.height = `${Math.round(h)}px`;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const cw = Math.round(w * dpr);
    const ch = Math.round(h * dpr);
    if (canvas.width !== cw || canvas.height !== ch) { canvas.width = cw; canvas.height = ch; }
    const r = cropRect();
    const ctx = canvas.getContext('2d');
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, cw, ch);
    const k = cw / r.w;
    ctx.setTransform(k, 0, 0, k, -r.x * k, -r.y * k);
    drawRotated(ctx);
    $('#crop-zoom').value = String(crop.zoom);
  }

  function scheduleCrop() {
    if (!crop.raf) crop.raf = requestAnimationFrame(() => { crop.raf = 0; renderCrop(); });
  }

  function setZoom(z) {
    crop.zoom = Math.min(6, Math.max(1, z));
    scheduleCrop();
  }

  function centerCrop() {
    const [W, H] = rotSize();
    crop.cx = W / 2;
    crop.cy = H / 2;
  }

  function cropOutput() {
    const r = cropRect();
    const scale = Math.min(1, OUT_MAX / Math.max(r.w, r.h));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(r.w * scale));
    canvas.height = Math.max(1, Math.round(r.h * scale));
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.imageSmoothingQuality = 'high';
    ctx.setTransform(scale, 0, 0, scale, -r.x * scale, -r.y * scale);
    drawRotated(ctx);
    return canvas;
  }

  function paintRatioChips() {
    $$('#crop-ratios .chip').forEach((c) => c.classList.toggle('active', c.dataset.ratio === crop.ratioKey));
  }

  // Opens the crop tool on a canvas. Resolves with { base64, url, state } or null if cancelled.
  function openCropper(src, state) {
    Object.assign(crop, { src, rot: 0, ratioKey: '4:3', zoom: 1 });
    if (state) Object.assign(crop, state);
    else centerCrop();
    paintRatioChips();
    $('#cropper').hidden = false;
    document.body.classList.add('modal-open');
    requestAnimationFrame(renderCrop);
    return new Promise((resolve) => { crop.done = resolve; });
  }

  async function closeCropper(ok) {
    let result = null;
    if (ok) {
      const btn = $('#crop-ok');
      btn.disabled = true;
      try {
        const base64 = await canvasToBase64(cropOutput());
        result = {
          base64,
          url: `data:image/jpeg;base64,${base64}`,
          state: { rot: crop.rot, ratioKey: crop.ratioKey, zoom: crop.zoom, cx: crop.cx, cy: crop.cy },
        };
      } finally {
        btn.disabled = false;
      }
    }
    $('#cropper').hidden = true;
    document.body.classList.remove('modal-open');
    crop.pointers.clear();
    const done = crop.done;
    crop.done = null;
    if (done) done(result);
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
    const names = recipe.ingredients.map((e) => norm(`${ingName(e)} ${e.note || ''}`));
    const cats = recipeCats(recipe).map((id) => norm(catName(id)));
    return terms.every((t) => {
      const inTitle = title.includes(t);
      const inIngredients = names.some((n) => n.includes(t));
      if (searchMode === 'title') return inTitle;
      if (searchMode === 'ingredients') return inIngredients;
      return inTitle || inIngredients || cats.some((c) => c.includes(t));
    });
  }

  function catTags(r) {
    return el('div', { className: 'cat-tags' }, ...recipeCats(r).map((id) => el('span', { className: 'cat-tag' }, catName(id))));
  }

  // Category chips above the gallery. Several can be selected: a recipe must have all of them.
  function renderCatFilter(base) {
    for (const id of [...catFilter]) if (!catMap.has(id)) catFilter.delete(id);
    const counts = new Map();
    for (const r of base) for (const id of recipeCats(r)) counts.set(id, (counts.get(id) || 0) + 1);
    const shown = categories.filter((c) => counts.has(c.id) || catFilter.has(c.id)).sort(byName);
    $('#cat-filter').replaceChildren(...shown.map((c) => {
      const on = catFilter.has(c.id);
      const b = el('button', { type: 'button', className: 'ing-chip' + (on ? ' on' : '') },
        c.name, el('span', { className: 'chip-count' }, String(counts.get(c.id) || 0)));
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.addEventListener('click', () => {
        on ? catFilter.delete(c.id) : catFilter.add(c.id);
        renderGallery();
      });
      return b;
    }));
  }

  function toast(msg) {
    const t = $('#toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 1800);
  }

  function renderGallery() {
    const terms = norm($('#search').value).split(/[\s,]+/).filter(Boolean);
    const archivedCount = recipes.filter((r) => r.archived).length;
    if (!archivedCount) showArchived = false;
    const toggle = $('#archived-toggle');
    toggle.hidden = !archivedCount;
    toggle.textContent = showArchived ? '← Back to recipes' : `📦 Archived (${archivedCount})`;
    toggle.classList.toggle('active', showArchived);

    const base = recipes.filter((r) => !!r.archived === showArchived);
    renderCatFilter(base);
    const list = base.filter((r) => matches(r, terms) && [...catFilter].every((id) => r.categories.includes(id)));
    const grid = $('#grid');
    grid.replaceChildren();

    if (!base.length) {
      $('#status').textContent = archivedCount
        ? 'Every recipe is archived. Open “📦 Archived” to restore one, or add a new one in “+ New”.'
        : 'No recipe yet. Add your first one in the “+ New” tab.';
      return;
    }
    const noun = showArchived ? 'archived recipe' : 'recipe';
    $('#status').textContent = list.length
      ? `${list.length} ${noun}${list.length > 1 ? 's' : ''}`
      : 'No recipe matches your search.';

    for (const r of list) {
      const n = r.ingredients.length;
      const open = el('button', { className: 'card-open', type: 'button' },
        thumbFor(r, 'thumb'),
        el('div', { className: 'info' },
          el('div', { className: 'name' }, r.title),
          el('div', { className: 'meta' }, n ? `${n} ingredient${n > 1 ? 's' : ''}` : ''),
          catTags(r)));
      open.addEventListener('click', () => openDetail(r));
      const card = el('div', { className: 'card' + (r.archived ? ' archived' : '') }, open);

      // Quick add / remove from the grocery list, without opening the recipe
      if (!r.archived) {
        const inList = grocery.selected.includes(r.id);
        const label = inList ? `Remove “${r.title}” from the grocery list` : `Add “${r.title}” to the grocery list`;
        const cart = el('button', { type: 'button', className: 'card-cart' + (inList ? ' on' : ''), textContent: inList ? '✓' : '🛒', title: label });
        cart.setAttribute('aria-label', label);
        cart.setAttribute('aria-pressed', inList ? 'true' : 'false');
        cart.addEventListener('click', () => {
          toggleSelected(r.id, !inList);
          toast(inList ? 'Removed from the grocery list' : '🛒 Added to the grocery list');
        });
        card.append(cart);
      }
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
    closeRename();
    $('#d-cats').replaceChildren(...recipeCats(r).map((id) => el('span', { className: 'cat-tag' }, catName(id))));
    $('#d-archived').hidden = !r.archived;
    $('#d-archived-date').textContent = r.archivedAt ? ` on ${new Date(r.archivedAt).toLocaleDateString()}` : '';
    $('#d-grocery').hidden = !!r.archived;
    $('#archive-btn').textContent = r.archived ? '↩︎ Restore this recipe' : '📦 Archive this recipe';
    $('#archive-btn').className = r.archived ? 'primary' : 'archive';

    $('#d-ing-sec').hidden = !r.ingredients.length;
    $('#d-ingredients').replaceChildren(
      ...r.ingredients.map((e) =>
        el('li', { className: e.optional ? 'opt-ing' : '' },
          ...(e.quantity ? [el('span', { className: 'qty' }, e.quantity), ' '] : []),
          ingName(e),
          ...(e.note ? [' ', el('span', { className: 'note' }, `(${e.note})`)] : []),
          ...(e.optional ? [el('span', { className: 'opt-badge' }, 'optional')] : [])))
    );

    $('#d-steps-sec').hidden = !r.steps.length;
    $('#d-steps').replaceChildren(...r.steps.map((s) => el('li', {}, s)));

    updateDetailGrocery();
    if (!$('#detail').open) $('#detail').showModal();
    $('#detail').scrollTop = 0;
  }

  function openRename() {
    if (!current) return;
    $('#d-rename-input').value = current.title;
    $('#d-title-row').hidden = true;
    $('#d-rename-form').hidden = false;
    $('#d-rename-input').focus();
    $('#d-rename-input').select();
  }

  function closeRename() {
    $('#d-rename-form').hidden = true;
    $('#d-title-row').hidden = false;
    $('#d-rename-msg').textContent = '';
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

  function addIngredientRow(name = '', quantity = '', focus = false, note = '', optional = false) {
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
    const noteInput = el('input', { type: 'text', className: 'ing-note', placeholder: 'Comment (suprême, rouge…)', value: note });
    noteInput.setAttribute('aria-label', 'Comment');
    noteInput.setAttribute('autocomplete', 'off');
    noteInput.setAttribute('enterkeyhint', 'next');
    const optBox = el('input', { type: 'checkbox', className: 'ing-opt', checked: optional });
    const optLabel = el('label', { className: 'opt ing-opt-label' }, optBox, 'Optional');

    const refreshTag = () => {
      const v = splitNote(clean(nameInput.value), '').name;
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
      if (e.key === 'Enter') { e.preventDefault(); noteInput.focus(); }
    });
    noteInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); addIngredientRow('', '', true); }
    });

    const row = el('div', { className: 'ing-row' + (optional ? ' is-opt' : '') },
      el('div', { className: 'ing-main' }, el('div', { className: 'ing-name-wrap' }, nameInput, tag, box), qty, remove),
      el('div', { className: 'ing-extra' }, noteInput, optLabel));
    optBox.addEventListener('change', () => row.classList.toggle('is-opt', optBox.checked));
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
      .map((row) => {
        const { name, note } = splitNote(clean(row.querySelector('.ing-name').value), clean(row.querySelector('.ing-note').value));
        return {
          name,
          note,
          quantity: clean(row.querySelector('.ing-qty').value),
          optional: row.querySelector('.ing-opt').checked,
        };
      })
      .filter((x) => x.name);
  }

  /* ───────── create form: categories ───────── */

  function renderFormCats() {
    const known = categories.map((c) => c.name);
    const extra = formExtraCats.filter((n) => !known.some((k) => norm(k) === norm(n)));
    const all = [...known, ...extra].sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
    const selected = new Set(formCats.map(norm));
    $('#f-cats').replaceChildren(...all.map((name) => {
      const on = selected.has(norm(name));
      const b = el('button', { type: 'button', className: 'ing-chip' + (on ? ' on' : ''), textContent: (on ? '✓ ' : '') + name });
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      b.addEventListener('click', () => {
        formCats = on ? formCats.filter((n) => norm(n) !== norm(name)) : [...formCats, name];
        renderFormCats();
      });
      return b;
    }));
  }

  function addFormCategory() {
    const typed = clean($('#f-cat-new').value);
    if (!typed) return;
    const known = categories.find((c) => norm(c.name) === norm(typed)) ||
      { name: formExtraCats.find((n) => norm(n) === norm(typed)) };
    const name = known.name || typed.charAt(0).toUpperCase() + typed.slice(1);
    if (!known.name) formExtraCats.push(name);
    if (!formCats.some((n) => norm(n) === norm(name))) formCats.push(name);
    $('#f-cat-new').value = '';
    renderFormCats();
  }

  const formCatIds = (list) => [...new Set(formCats.map((n) => getOrCreateCategory(list, n).id))];

  function formSay(text, isError) {
    const msg = $('#create-msg');
    msg.textContent = text;
    msg.classList.toggle('error', !!isError);
    if (text) msg.scrollIntoView({ block: 'nearest' });
  }

  function resetCreateForm() {
    $('#create-form').reset();
    $('#ing-rows').replaceChildren();
    addIngredientRow();
    $('#create-msg').textContent = '';
    editing = null;
    pendingPicture = null;
    formCats = [];
    formExtraCats = [];
    renderFormCats();
    updateFormMode();
    showCurrentPicture();
  }

  // Switches the “+ New” form between creating and editing.
  function updateFormMode() {
    const on = !!editing;
    $('#edit-banner').hidden = !on;
    $('#f-remove-wrap').hidden = !(on && editing.image);
    $('#save-btn').textContent = on ? 'Save changes' : 'Save recipe';
    $('.tab[data-tab="create"]').textContent = on ? '✏️ Edit' : '+ New';
    if (on) $('#edit-name').textContent = editing.title;
  }

  // Preview: the newly chosen picture, else the current one (edit mode), else nothing.
  function showCurrentPicture() {
    const preview = $('#preview');
    const hasCurrent = !!(editing && editing.image && !$('#f-remove-image').checked);
    if (pendingPicture) {
      preview.onerror = null;
      preview.src = pendingPicture.url;
      preview.hidden = false;
    } else if (hasCurrent) {
      loadImage(preview, { title: editing.title, image: editing.image });
      preview.loading = 'eager';
      preview.hidden = false;
    } else {
      preview.hidden = true;
      preview.removeAttribute('src');
    }
    $('#f-adjust').hidden = !(pendingPicture || hasCurrent);
    $('#f-image-btn').textContent = pendingPicture || hasCurrent ? '🖼️ Change picture' : '🖼️ Choose a picture';
  }

  function startEdit(r) {
    resetCreateForm();
    editing = { id: r.id, image: r.image, title: r.title };
    $('#f-title').value = r.title;
    $('#ing-rows').replaceChildren();
    r.ingredients.forEach((e) => addIngredientRow(ingName(e), e.quantity || '', false, e.note || '', !!e.optional));
    if (!r.ingredients.length) addIngredientRow();
    $('#f-steps').value = r.steps.join('\n');
    formCats = recipeCats(r).map(catName);
    renderFormCats();
    updateFormMode();
    showCurrentPicture();
    if ($('#detail').open) $('#detail').close();
    showTab('create');
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
    const ids = new Set(activeRecipes().map((r) => r.id));
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
    renderGallery();
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
    const active = activeRecipes();
    for (const r of active) {
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
    for (const r of active) {
      if (!selected.has(r.id)) continue;
      if (!r.ingredients.length) withoutIngredients.push(r.title);
      for (const e of r.ingredients) {
        let item = items.get(e.ingredientId);
        if (!item) items.set(e.ingredientId, (item = { id: e.ingredientId, name: ingName(e), uses: [] }));
        item.uses.push({ recipe: r.title, quantity: e.quantity || '', note: e.note || '', optional: !!e.optional });
      }
    }
    // An ingredient is optional in the list only if every selected recipe marks it optional.
    for (const item of items.values()) item.optional = item.uses.every((u) => u.optional);

    const sorted = [...items.values()].sort((a, b) =>
      (checked.has(a.id) - checked.has(b.id)) || (a.optional - b.optional) || byName(a, b));

    lastGroceryItems = sorted;
    const list = $('#g-list');
    list.replaceChildren();
    for (const item of sorted) {
      const done = checked.has(item.id);
      const cb = el('input', { type: 'checkbox', checked: done });
      cb.addEventListener('change', () => toggleChecked(item.id, cb.checked));
      list.append(
        el('li', { className: 'g-item' + (done ? ' done' : '') + (item.optional ? ' optional' : '') },
          el('label', { className: 'g-main' }, cb, el('span', { className: 'g-name' }, item.name),
            item.optional ? el('span', { className: 'opt-badge' }, 'optional') : ''),
          el('ul', { className: 'g-uses' },
            ...item.uses.map((u) =>
              el('li', {}, el('span', { className: 'g-recipe' }, u.recipe),
                useDetail(u) ? el('span', { className: 'g-qty' }, ` — ${useDetail(u)}`) : '',
                u.optional && !item.optional ? el('span', { className: 'opt-badge' }, 'optional') : ''))))
      );
    }

    // 3. Messages
    const doneCount = sorted.filter((i) => checked.has(i.id)).length;
    $('#g-summary').textContent = sorted.length ? `${sorted.length} item${sorted.length > 1 ? 's' : ''} · ${doneCount} checked` : '';

    let msg = '';
    if (!active.length) msg = 'Add some recipes first.';
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
      out.push(`${checked.has(item.id) ? '☑' : '☐'} ${item.name}${item.optional ? ' (optional)' : ''}`);
      if (withRecipes) {
        for (const u of item.uses) {
          const d = useDetail(u);
          out.push(`    ${u.recipe}${d ? ` — ${d}` : ''}${u.optional && !item.optional ? ' [optional]' : ''}`);
        }
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

    // 1. Selected ingredients
    const sel = $('#c-selected');
    const selected = pantry.have.map((id) => ingMap.get(id)).filter(Boolean).sort(byName);
    sel.replaceChildren(...selected.map((i) => cookChip(i, true)));
    $('#c-count').textContent = selected.length ? `(${selected.length})` : '';
    $('#c-clear').hidden = !selected.length;

    // 2. Library, filtered, only ingredients used by at least one recipe (most used first)
    const active = activeRecipes();
    const used = new Map();
    for (const r of active) for (const e of new Set(r.ingredients.map((x) => x.ingredientId))) used.set(e, (used.get(e) || 0) + 1);
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
    for (const r of active) {
      if (!r.ingredients.length) { noIng++; continue; }
      // Optional ingredients never block a recipe; they are only listed as a bonus.
      const required = [...new Set(r.ingredients.filter((e) => !e.optional).map((e) => e.ingredientId))];
      const optional = [...new Set(r.ingredients.filter((e) => e.optional).map((e) => e.ingredientId))]
        .filter((id) => !required.includes(id));
      const missing = required.filter((id) => !have.has(id));
      const owned = required.length - missing.length;
      const optMissing = optional.filter((id) => !have.has(id));
      const res = { r, missing, owned, total: required.length, optMissing, optTotal: optional.length };
      if (!missing.length) can.push(res);
      else if (owned > 0 && missing.length <= pantry.maxMissing) almost.push(res);
    }
    can.sort((a, b) => b.total - a.total || a.r.title.localeCompare(b.r.title));
    almost.sort((a, b) => a.missing.length - b.missing.length || b.owned / b.total - a.owned / a.total || a.r.title.localeCompare(b.r.title));

    const entryText = (r, id) => {
      const e = r.ingredients.find((x) => x.ingredientId === id) || {};
      const d = useDetail(e);
      return ((ingMap.get(id) || {}).name || id) + (d ? ` ${d.startsWith('(') ? d : `(${d})`}` : '');
    };
    const resultCard = ({ r, missing, owned, total, optMissing, optTotal }) => {
      const meta = `${owned}/${total} ingredients` + (optTotal ? ` · optional ${optTotal - optMissing.length}/${optTotal}` : '');
      const open = el('button', { type: 'button', className: 'c-open' },
        thumbFor(r, 'pick-thumb'),
        el('span', { className: 'c-info' },
          el('span', { className: 'pick-title' }, r.title),
          el('small', { className: 'muted' }, meta)));
      open.addEventListener('click', () => openDetail(r));
      const inList = grocery.selected.includes(r.id);
      const add = el('button', { type: 'button', className: 'secondary small', textContent: inList ? '✓ In list' : '🛒 Add' });
      add.title = 'Add this recipe to the grocery list, with what you have already ticked';
      add.addEventListener('click', () => {
        if (!grocery.selected.includes(r.id)) grocery.selected = [...grocery.selected, r.id];
        markHaveInGrocery();
        renderGrocery();
        renderGallery();
        renderCook();
        updateDetailGrocery();
      });
      const card = el('li', { className: 'c-card' }, el('div', { className: 'c-row' }, open, add));
      if (missing.length) {
        card.append(el('div', { className: 'c-missing' },
          el('span', { className: 'muted' }, 'Missing: '),
          ...missing.map((id) => {
            const chip = el('button', { type: 'button', className: 'miss-chip', textContent: entryText(r, id) });
            chip.title = 'I have it';
            chip.addEventListener('click', () => toggleHave(id, true));
            return chip;
          })));
      }
      if (optMissing.length) {
        card.append(el('div', { className: 'c-optional muted' },
          'Optional, not needed: ', optMissing.map((id) => entryText(r, id)).join(', ')));
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
    $('#c-hint').textContent = !active.length
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
    renderFormCats();
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
  $$('.chip[data-mode]').forEach((chip) =>
    chip.addEventListener('click', () => {
      searchMode = chip.dataset.mode;
      $$('.chip[data-mode]').forEach((c) => c.classList.toggle('active', c === chip));
      renderGallery();
    })
  );
  $('#archived-toggle').addEventListener('click', () => {
    showArchived = !showArchived;
    renderGallery();
    window.scrollTo(0, 0);
  });

  // Detail dialog
  $('#close-detail').addEventListener('click', () => $('#detail').close());
  $('#detail').addEventListener('click', (e) => {
    if (e.target === $('#detail')) $('#detail').close(); // click on backdrop
  });
  $('#d-grocery').addEventListener('click', () => {
    if (current) toggleSelected(current.id, !grocery.selected.includes(current.id));
  });

  $('#edit-btn').addEventListener('click', () => { if (current) startEdit(current); });

  // Quick rename from the recipe page
  $('#d-rename').addEventListener('click', openRename);
  $('#d-rename-cancel').addEventListener('click', closeRename);
  $('#d-rename-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!current) return;
    const title = clean($('#d-rename-input').value);
    if (!title) { $('#d-rename-msg').textContent = 'The name cannot be empty.'; return; }
    if (title === current.title) { closeRename(); return; }
    const id = current.id;
    const btn = $('#d-rename-save');
    btn.disabled = true;
    try {
      await commitData((d) => {
        const r = d.recipes.find((x) => x.id === id);
        if (!r) throw new Error('This recipe no longer exists.');
        r.title = title;
        r.updatedAt = new Date().toISOString();
      }, `Rename recipe: ${title}`);
      if (editing && editing.id === id) {
        editing.title = title;
        $('#f-title').value = title;
        updateFormMode();
      }
      refreshAll();
      const r = recipes.find((x) => x.id === id);
      if (r) openDetail(r);
    } catch (ex) {
      $('#d-rename-msg').textContent = `Could not rename: ${ex.message}`;
    } finally {
      btn.disabled = false;
    }
  });

  // Archive / restore: the recipe is kept in the repo, only flagged. Nothing is ever deleted.
  $('#archive-btn').addEventListener('click', async () => {
    if (!current) return;
    const target = current;
    const archive = !target.archived;
    if (archive && !confirm(`Archive “${target.title}”?\n\nIt will be hidden from the gallery, grocery and cook tabs. You can restore it at any time from “📦 Archived”.`)) return;
    const btn = $('#archive-btn');
    btn.disabled = true;
    try {
      await commitData((d) => {
        const r = d.recipes.find((x) => x.id === target.id);
        if (!r) throw new Error('This recipe no longer exists.');
        if (archive) {
          r.archived = true;
          r.archivedAt = new Date().toISOString();
        } else {
          delete r.archived;
          delete r.archivedAt;
        }
      }, `${archive ? 'Archive' : 'Restore'} recipe: ${target.title}`);
      $('#detail').close();
      current = null;
      if (!archive) showArchived = false;
      refreshAll();
    } catch (ex) {
      alert(`Could not ${archive ? 'archive' : 'restore'}: ${ex.message}`);
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

  // Pictures: read (any format the phone can give), then crop, then keep the result until saving.
  $('#f-image-btn').addEventListener('click', () => $('#f-image').click());

  $('#f-image').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    formSay('Reading the picture…');
    try {
      const work = await loadPicture(file, formSay);
      formSay('');
      const res = await openCropper(work);
      if (res) {
        pendingPicture = { work, ...res };
        $('#f-remove-image').checked = false;
      }
    } catch (ex) {
      formSay(ex.message, true);
    } finally {
      e.target.value = ''; // the same file can be chosen again
      showCurrentPicture();
    }
  });

  $('#f-adjust').addEventListener('click', async () => {
    try {
      let work = pendingPicture && pendingPicture.work;
      const state = pendingPicture && pendingPicture.state;
      if (!work) {
        formSay('Loading the current picture…');
        work = await loadPicture(await fetchPicture(editing.image), formSay);
        formSay('');
      }
      const res = await openCropper(work, state);
      if (res) pendingPicture = { work, ...res };
    } catch (ex) {
      formSay(ex.message, true);
    }
    showCurrentPicture();
  });

  $('#f-remove-image').addEventListener('change', () => {
    if ($('#f-remove-image').checked) pendingPicture = null;
    showCurrentPicture();
  });

  // Crop tool
  $('#crop-cancel').addEventListener('click', () => closeCropper(false));
  $('#crop-ok').addEventListener('click', () => closeCropper(true));
  $('#crop-rotate').addEventListener('click', () => {
    crop.rot = (crop.rot + 90) % 360;
    centerCrop();
    scheduleCrop();
  });
  $('#crop-reset').addEventListener('click', () => {
    crop.rot = 0;
    crop.zoom = 1;
    centerCrop();
    scheduleCrop();
  });
  $$('#crop-ratios .chip').forEach((chip) => chip.addEventListener('click', () => {
    crop.ratioKey = chip.dataset.ratio;
    paintRatioChips();
    scheduleCrop();
  }));
  $('#crop-zoom').addEventListener('input', () => setZoom(Number($('#crop-zoom').value)));

  const stage = $('#crop-stage');
  const pinchDist = () => {
    const p = [...crop.pointers.values()];
    return p.length === 2 ? Math.hypot(p[0].x - p[1].x, p[0].y - p[1].y) : 0;
  };
  stage.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    try { stage.setPointerCapture(e.pointerId); } catch (_) { /* ignore */ }
    crop.pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    crop.pinch = pinchDist();
  });
  stage.addEventListener('pointermove', (e) => {
    const p = crop.pointers.get(e.pointerId);
    if (!p || !crop.src) return;
    const dx = e.clientX - p.x;
    const dy = e.clientY - p.y;
    p.x = e.clientX;
    p.y = e.clientY;
    if (crop.pointers.size === 1) {
      const k = cropRect().w / stage.clientWidth;
      crop.cx -= dx * k;
      crop.cy -= dy * k;
      scheduleCrop();
    } else if (crop.pointers.size === 2) {
      const d = pinchDist();
      if (crop.pinch) setZoom(crop.zoom * (d / crop.pinch));
      crop.pinch = d;
    }
  });
  const endPointer = (e) => {
    crop.pointers.delete(e.pointerId);
    crop.pinch = pinchDist();
  };
  ['pointerup', 'pointercancel', 'lostpointercapture'].forEach((t) => stage.addEventListener(t, endPointer));
  stage.addEventListener('wheel', (e) => {
    e.preventDefault();
    setZoom(crop.zoom * Math.exp(-e.deltaY / 400));
  }, { passive: false });
  window.addEventListener('resize', () => { if (!$('#cropper').hidden) scheduleCrop(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('#cropper').hidden) closeCropper(false);
  });

  // Categories in the form
  $('#f-cat-add').addEventListener('click', addFormCategory);
  $('#f-cat-new').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); addFormCategory(); }
  });

  $('#edit-cancel').addEventListener('click', () => {
    const id = editing && editing.id;
    resetCreateForm();
    showTab('gallery');
    const r = recipes.find((x) => x.id === id);
    if (r) openDetail(r);
  });

  // Best effort: an unused picture left behind is harmless.
  async function deletePicture(path, title) {
    try {
      const file = await getFile(path);
      if (file) await gh(contentsPath(path), {
        method: 'DELETE',
        body: JSON.stringify({ message: `Remove old picture: ${title}`, sha: file.sha, branch: cfg.branch }),
      });
    } catch (_) { /* ignore */ }
  }

  $('#create-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#save-btn');
    const msg = $('#create-msg');
    const title = clean($('#f-title').value);

    const say = formSay;

    if (!title) {
      say('Please enter a recipe name.', true);
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

    if (editing) {
      const { id, image: oldImage } = editing;
      try {
        let image = oldImage;
        if (pendingPicture) {
          say('Uploading picture…');
          // A new file name, so phones do not keep showing the old cached picture
          const path = `images/${id}-${Date.now().toString(36)}.jpg`;
          await putFile(path, pendingPicture.base64, `Change picture: ${title}`);
          image = path;
        } else if ($('#f-remove-image').checked) {
          image = null;
        }

        say('Saving changes…');
        await commitData((d) => {
          const r = d.recipes.find((x) => x.id === id);
          if (!r) throw new Error('This recipe no longer exists.');
          r.title = title;
          r.ingredients = entries.map((x) => toEntry(d.ingredients, x));
          r.categories = formCatIds(d.categories);
          r.steps = steps;
          r.image = image;
          r.updatedAt = new Date().toISOString();
        }, `Edit recipe: ${title}`);

        if (oldImage && oldImage !== image) await deletePicture(oldImage, title);

        resetCreateForm();
        showTab('gallery');
        refreshAll();
        const saved = recipes.find((x) => x.id === id);
        if (saved) openDetail(saved);
      } catch (ex) {
        say(`Could not save: ${ex.message}`, true);
      } finally {
        btn.disabled = false;
        updateFormMode();
      }
      return;
    }

    try {
      const id = `${slug(title).slice(0, 40) || 'recipe'}-${Date.now().toString(36)}`;
      const recipe = { id, title, image: null, categories: [], ingredients: [], steps, createdAt: new Date().toISOString() };

      if (pendingPicture) {
        say('Uploading picture…');
        const path = `images/${id}.jpg`;
        await putFile(path, pendingPicture.base64, `Add picture: ${title}`);
        recipe.image = path;
      }

      say('Saving recipe…');
      await commitData((d) => {
        recipe.ingredients = entries.map((x) => toEntry(d.ingredients, x));
        recipe.categories = formCatIds(d.categories);
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
      updateFormMode();
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
