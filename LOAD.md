# Load the extension (2 minutes)

**You must load the `dist/` folder — not the repo root.**

```bash
cd FINAL          # or wherever you cloned surakshanet
npm install
npm run build
```

Then in Chrome:

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the **`dist`** folder inside this repo  
   Example: `.../surakshanet/dist`  
   **NOT** the parent `surakshannet v2` folder  
   **NOT** the repo root (no `dist` inside = will fail)

5. Open **https://web.whatsapp.com** and open any chat

If load fails, check **Errors** on the extension card — usually means you picked the wrong folder.

After code changes always run `npm run build` and click **Reload** on the extension.
