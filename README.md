# SafeScan (Flask + NLP) - Mobile Install (Samsung/Android)

This project is a Flask web app that checks:
- URLs (simple phishing heuristics)
- Text (NLP classifier)
- Full emails (text + extracted URLs)

It is also set up as a PWA (Progressive Web App), so users can "install" it to their phone from the browser.

## Run Locally

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open:
- http://127.0.0.1:5000/?lang=en
- http://127.0.0.1:5000/?lang=ar

## Train / Improve The NLP Model

Scikit-learn (default model used by the Flask app):

```powershell
python train.py
python export_offline_model.py
```

`train.py` now loads and merges both datasets automatically:
- `messages.csv` (`text`,`label`)
- `spam/spam.csv` (`v1`,`v2` with `ham/spam`)
- `spam/arabic_expanded.csv` (large Arabic safe/unsafe set)
- `URL dataset.csv` (`url`,`type`) and `Phishing URLs.csv` (`url`,`Type`)

`train.py` trains and evaluates multiple algorithms:
- Logistic Regression (baseline + offline export compatibility)
- Decision Tree
- Random Forest
- MLP Neural Network

It also saves:
- `ensemble_models.pkl` (weighted ensemble bundle used by Flask app)
- `training_report.json` (validation metrics and source stats)

Optional: TensorFlow model (experiment / ensemble):

```powershell
pip install -r requirements-tf.txt
python train_tf.py
```

To use the saved TensorFlow model in the web app (optional):

```powershell
$env:SAFESCAN_USE_TF = "1"
python app.py
```

## Best Way To Share On Samsung Phones (Recommended)

You need a public **HTTPS** URL (a free host subdomain is fine) for PWA install + auto-updates.

Two good options:

1) **Hosted PWA (server)**: deploy this Flask app to a public HTTPS URL. People open the URL and tap **Install**.
   - Best if you want the NLP model to run on the server.
   - When you redeploy with new code, the installed PWA will update.

2) **Static PWA (no server)**: deploy the offline version (`offline/`) to a static host (example: GitHub Pages).
   - Best if you want **no backend server** and still want an installable app.
   - When you upload a new version, users get the update the next time they open the app online.

## Deploy (Example: Render)

Render is a simple option for Flask apps.

1) Put this project in a GitHub repository (include `model.pkl` and `vectorizer.pkl`).
2) Create a new Render **Web Service** from that repo.
3) Use:
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`
4) Set an environment variable:
   - `FLASK_SECRET_KEY` = a long random string
5) After deploy, open the provided HTTPS URL on your phone.

## Deploy Offline PWA to GitHub Pages (Free HTTPS + Auto Updates)

This repo includes a GitHub Actions workflow that publishes the offline app (`offline/`) to GitHub Pages.

1) Create a GitHub repo and push this project (branch `main`).
2) In GitHub: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
3) After the workflow runs, your URL will look like: `https://<username>.github.io/<repo>/`

Update flow:
- Change the code (mainly inside `offline/`), push to `main`, and GitHub Pages updates automatically.

APK links (optional):
- `https://<username>.github.io/<repo>/downloads/SafeScan.apk`

## Install On Samsung / Android

- Open the HTTPS site in Chrome or Samsung Internet.
- If the **Install** button appears in the header, tap it.
- Or use the browser menu: **Install app** / **Add to Home screen**.

## Optional: Make An APK Download (Web Download)

If you want users to download an APK file from a webpage:
1) Deploy the PWA (you need a public HTTPS URL first).
2) Use a PWA-to-Android packager (example: https://www.pwabuilder.com/) and generate an Android package.
3) Upload the APK to your website so users can download and install it.

Note: APK install usually requires enabling "Install unknown apps" on the phone.

### Quick APK Update (after PWABuilder download)

After you download an `*unsigned.apk` from PWABuilder, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\update_apk.ps1
```

This script will:
- find the newest `*unsigned.apk` in your Downloads folder
- align + sign it with `zipalign`/`apksigner` using your local Android debug keystore
- replace `static/downloads/SafeScan.apk` and `static/downloads/SafeScanOffline.apk`

If `apksigner` is missing, install Android SDK Build-Tools (for example `34.0.0`).

## Offline Android App (No Domain Needed)

This repo also contains a fully offline version that runs on the phone (no server).

- Offline web app (static): `offline/index.html`
- Prebuilt APK (debug): `static/downloads/SafeScan.apk`

Install:
- Copy `static/downloads/SafeScan.apk` to the phone
- Open it and install (Android may ask to allow installing from unknown sources)
