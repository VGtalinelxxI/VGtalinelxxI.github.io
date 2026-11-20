# cookbook

A personal recipe book hosted on GitHub Pages. Phone friendly.

- **Gallery** with search by title and/or ingredients
- **+ New** tab to add a recipe (title, picture, ingredients, steps)
- Recipes are stored in `data/recipes.json`, pictures in `images/`, both committed to this repo
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

## How the lock works (please read)

GitHub Pages is static hosting, so there is no server to check a password. Instead:

- Your GitHub token is encrypted in the browser (PBKDF2 + AES-GCM) with your password. Only the encrypted version is published in `config.json`.
- Without the password nobody can open the app or write to your repo.
- Because the encrypted token is public, a **short or common password can be brute-forced offline**. Use a long passphrase.
- The repository is public, so the recipes and pictures themselves can technically be read by anyone who knows the repo URL. This protects *editing and the app*, not the confidentiality of the content. If you need private recipes, use a private repository (GitHub Pages for private repos requires a paid plan) and ask for changes.
- Limit the token to this single repository, as in step 4. If you ever doubt it, revoke it on GitHub and run the setup again (delete `config.json` first).

## Data format

```json
{
  "id": "chocolate-cake-lq3x9",
  "title": "Chocolate cake",
  "image": "images/chocolate-cake-lq3x9.jpg",
  "ingredients": ["200 g flour", "3 eggs"],
  "steps": ["Preheat the oven", "Mix everything"],
  "createdAt": "2026-11-20T21:00:00.000Z"
}
```
