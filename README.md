# Chrome Extension Compliance Pack

Free local preflight for Manifest V3 Chrome extensions. Open the extension ZIP in the page: the package is read in the browser, never uploaded and never executed. Every check maps to an official Chrome Web Store violation ID from the [troubleshooting page](https://developer.chrome.com/docs/webstore/troubleshooting) (Purple Potassium, Blue Argon, Yellow Zinc, Yellow Magnesium, Purple Lithium, Purple Nickel, Purple Copper, Red Titanium). Optional checks for Firefox Add-ons (gecko id, data_collection_permissions, background scripts, source code submission) and Microsoft Edge Add-ons (policy 1.1.2).

Live: https://nicolaplantiverse.github.io/chrome-extension-compliance-pack/

## Run locally

```sh
python3 -m http.server 4173
```

Open `http://localhost:4173/`. A local server is only needed because browser ES modules do not load from `file://`.

## Test

```sh
node tests/run-tests.mjs
```

## The paid pack

The EUR 29 pack (rejection playbook, permission justifications, templates, offline command line tool) is sold by ECOBUBBLE S.R.L. and is not in this repository. See the [product page](https://nicolaplantiverse.github.io/chrome-extension-compliance-pack/#pricing) and the [terms](https://nicolaplantiverse.github.io/chrome-extension-compliance-pack/terms.html).

Not affiliated with or endorsed by Google. Chrome and Chrome Web Store are trademarks of Google LLC.

© 2026 ECOBUBBLE S.R.L. All rights reserved.
