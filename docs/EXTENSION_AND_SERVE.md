# Grym Browser Extension & `grym serve` Guide

This guide covers installing the Grym browser extension and running the local `grym serve` API that powers the extension.

---

## Running `grym serve`

The CLI ships a local HTTP server that exposes the scanner, CVE database, exploit generator, and zero-day predictor.

```bash
# Build the CLI (only needed once)
cargo build -p grym-cli --release

# Start the server on the default host/port (127.0.0.1:9378)
cargo run -p grym-cli -- serve

# Or specify a different bind address
cargo run -p grym-cli -- serve --host 127.0.0.1 --port 9378
```

The server uses a development scope that allows traffic to all targets. In production, pass an explicit scope file:

```bash
grym serve --scope ./scope.json
```

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Server health check |
| POST | `/scan` | Run scanner modules against a target |
| GET | `/findings` | List stored findings from this session |
| GET | `/cve-db` | Full CVE database (130+ entries) |
| GET | `/cve/{id}` | Lookup a single CVE by ID |
| POST | `/cve-lookup` | Correlate CVEs against a component fingerprint |
| POST | `/exploit` | Generate a PoC/exploit from a CVE |
| POST | `/predict` | Zero-day prediction for a component + version |
| POST | `/analyze-body` | Predict vulnerabilities from a response body |
| GET | `/state` | Server runtime state |

### Example: scan a target

```bash
curl -X POST http://localhost:9378/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"http://localhost:8080","scan_types":["all"]}'
```

### Example: generate an exploit

```bash
curl -X POST http://localhost:9378/exploit \
  -H "Content-Type: application/json" \
  -d '{"cve_id":"CVE-2021-44228","format":"python","target":"http://target:8080"}'
```

### Example: predict zero-day risk

```bash
curl -X POST http://localhost:9378/predict \
  -H "Content-Type: application/json" \
  -d '{"component":"Apache Struts","version":"2.5.10"}'
```

---

## Installing the Browser Extension

The extension is a Manifest V3 add-on that works in Chromium, Firefox, and Edge.

### Chrome / Edge (developer load)

1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer mode**.
3. Click **Load unpacked**.
4. Select the `browser-ext/` directory.
5. Pin the Grym icon to the toolbar.

### Firefox (temporary load)

1. Open `about:debugging`.
2. Click **This Firefox** → **Load Temporary Add-on**.
3. Select `browser-ext/manifest.json`.

### Using the extension

1. Make sure `grym serve` is running on `http://localhost:9378` (or update the server URL in Settings).
2. Click the Grym toolbar icon to open the popup.
3. Click **Dashboard** to open the full-page scanner UI.
4. Use the tabs to:
   - **Scanner** — choose modules and run scans.
   - **Findings** — review, filter, and export results.
   - **CVE DB** — search and load the CVE database.
   - **Exploit Gen** — generate PoCs from CVEs.
   - **Predict** — run zero-day risk prediction for a component/version.

### Permissions

The extension requests `storage`, `activeTab`, `scripting`, `tabs`, and broad host permissions so it can analyze the current page and communicate with the local Grym server. All active scanning is delegated to the local `grym serve` process and respects the loaded scope.

---

## Cross-origin notes

The `grym serve` API enables CORS so the extension can call it directly from `chrome-extension://` origins. If you run the server on a non-default host or port, set the same endpoint in the extension Settings tab.
