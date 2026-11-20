# cookbook

A personal recipe book hosted on GitHub Pages. Phone friendly.

- **Gallery** with search by title and/or ingredients
- **+ New** tab to add a recipe. Only the **title** is mandatory; picture, ingredients and steps are optional
- **Ingredients are reusable objects**: pick one from your library or type a new name, it is created once and shared by all recipes
- **🛒 Grocery** tab: tick the recipes you plan to cook, get one checklist of ingredients showing which recipe needs each one (and how much)
- **Edit** any recipe after creation (✏️ Edit in the recipe): title, picture, ingredients, steps
- **Archive instead of delete**: archived recipes are hidden but kept, and can be restored at any time from *📦 Archived* in the gallery
- **Export the grocery list with its ticks**: Share, Copy, Download .txt, Print / PDF, or a *Link with ticks* that rebuilds the same list on another device
- **🥕 Cook** tab: tap the ingredients you have, see the recipes you can make and the ones you can *almost* make, with the missing ingredients listed
- Everything is stored in this repo: recipes in `data/recipes.json`, the ingredient library in `data/ingredients.json`, pictures in `images/`
- Locked by a password, asked **once per device**

## Install (5 minutes)

1. **Create a public repository** on GitHub named `cookbook`.
2. **Upload all the files of this folder** to it (drag and drop in the GitHub web page works, keep the `data/` and `images/` folders).
3. **Enable GitHub Pages**: *Settings → Pages → Build and deployment → Deploy from a branch → `main` / `(root)`*.
   The site will be at `https://<your-name>.github.io/cookbook/`.
4. **Create a token**: <https://github.com/settings/personal-access-tokens/new>
   - Repository access: *Only select repositories* → `cookbook`
   - Permissions → Repository permissions → **Contents: Read and write**
5. **Open the site.** The first time, a setup screen asks for the repository (`your-name/cookbook`), the token and the password you want.
   The app encrypts the token with your password and saves it as `config.json` in the repo.
6. On every other device, open the site and type the password **once**. The device then remembers it (use the 🔒 button to forget it).

On a phone, use *Share → Add to Home Screen* to get an app icon.

## Updating an existing cookbook

Replace `index.html`, `app.js`, `style.css` and `README.md` in the repo.
On the phone, force a refresh after the update (close the app completely, or clear the website data) so the new `app.js` is loaded. **Do not touch `data/`, `images/` or `config.json`.**
GitHub Pages can take a minute or two to publish; refresh the page (pull to refresh, or close and reopen the app).

Recipes created with the first version (ingredients as plain text lines such as `250 g flour`) are converted automatically:
the quantity and the name are split, and the names go into the ingredient library. The converted data is written to the repo the next time you save anything.

## Grocery mode

Open the **🛒 Grocery** tab (or tap *Add to grocery list* inside a recipe), tick the recipes you want, and the list below builds itself:

```
☐ Flour
    Crêpes — 250 g
    Chocolate cake — 200 g
☐ Eggs
    Crêpes — 3
```

Tick items as you shop; checked items go to the bottom. The selection and the ticks are kept on the device (not in the repo), so each phone has its own shopping list.

## Edit a recipe

Open a recipe and tap **✏️ Edit**. The form opens pre-filled (the tab shows *✏️ Edit*). Change anything, then **Save changes**, or **Cancel**.
For the picture: choose a new file to replace it, or tick *Remove the current picture*. The old picture file is removed from the repo.

## Archive (no more delete)

**📦 Archive this recipe** hides the recipe from the gallery, the grocery tab and the cook tab. Nothing is deleted: the recipe and its picture stay in the repo.
The gallery shows a **📦 Archived (n)** button when at least one recipe is archived. Open it, tap a recipe, then **↩︎ Restore this recipe**.

## Export the grocery list

Under the list, *Export the list*:

- **Include checked items**: keep the ☑ lines (otherwise only what is left to buy is exported)
- **Share** opens the phone share sheet (Messages, WhatsApp, Notes…). **Copy** puts the text in the clipboard. **Download** saves a `.txt` file
- **Print / PDF** prints only the list, ticks included (choose *Save as PDF* in the print dialog)
- **Link with ticks** creates a link; opening it on another device restores the same recipes and the same ticks

```
🛒 Shopping list — 20/11/2026

☑ Flour
    Crêpes — 250 g
☐ Eggs
    Crêpes — 3
```

## Cook mode (🥕)

Tap the ingredients you have (or type in the search box and press Enter). The app shows:

- **✅ You can make**: every ingredient of the recipe is selected
- **🟡 Almost**: recipes missing at most *N* ingredients (choose 1 to 5); the missing ones are listed with their quantity. Tap a missing ingredient if you actually have it
- **🛒 Add** puts the recipe in the grocery list and ticks what you already have, so only the missing items remain

Your selection is remembered on the device.

## How the lock works (please read)

GitHub Pages is static hosting, so there is no server to check a password. Instead:

- Your GitHub token is encrypted in the browser (PBKDF2 + AES-GCM) with your password. Only the encrypted version is published in `config.json`.
- Without the password nobody can open the app or write to your repo.
- Because the encrypted token is public, a **short or common password can be brute-forced offline**. Use a long passphrase.
- The repository is public, so the recipes and pictures themselves can technically be read by anyone who knows the repo URL. This protects *editing and the app*, not the confidentiality of the content. If you need private recipes, use a private repository (GitHub Pages for private repos requires a paid plan).
- Limit the token to this single repository, as in step 4. If you ever doubt it, revoke it on GitHub and run the setup again (delete `config.json` first).

## Data format

`data/ingredients.json`

```json
[
  { "id": "flour", "name": "Flour" },
  { "id": "eggs", "name": "Eggs" }
]
```

`data/recipes.json`

```json
[
  {
    "id": "chocolate-cake-lq3x9",
    "title": "Chocolate cake",
    "image": "images/chocolate-cake-lq3x9.jpg",
    "ingredients": [
      { "ingredientId": "flour", "quantity": "200 g" },
      { "ingredientId": "eggs", "quantity": "3" }
    ],
    "steps": ["Preheat the oven", "Mix everything"],
    "createdAt": "2026-11-20T21:00:00.000Z"
  }
]
```

`image` is `null` when there is no picture; `ingredients` and `steps` can be empty.
Edited recipes get an `updatedAt` date. Archived recipes get `"archived": true` and an `archivedAt` date.
