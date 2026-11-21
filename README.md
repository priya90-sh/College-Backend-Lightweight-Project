# College Shield — Flask ML API (Vercel trial deployment)

This repository contains the Flask backend used by the College Shield React frontend.
It keeps the existing MongoDB, YOLO, EasyOCR, and DeepFace paths; no mock prediction path is added.

## Vercel setup

- Import this repository as a new Vercel project.
- Framework preset: Flask (or allow automatic detection).
- Root directory: `./`.
- Leave build command and output directory empty/default; Vercel detects the Flask WSGI app from `app.py`.
- Python version: `.python-version` pins 3.12.
- Dependencies: `requirements.txt` contains runtime dependencies only. `gunicorn` is intentionally omitted because Vercel invokes the WSGI `app` directly.
- `vercel.json` configures a 300-second maximum duration, includes the YOLO weights, and excludes test/debug files.

## Required Vercel environment variables

Set these in Project Settings → Environment Variables for Preview and Production:

- `MONGODB_URI` — MongoDB Atlas connection string (secret).
- `DB_NAME` — normally `entry_shield`.
- `FRONTEND_ORIGINS` — exact frontend Vercel origin, e.g. `https://college-shield-frontend.vercel.app` (no trailing slash).
- `EASYOCR_MODEL_DIR` — `/tmp/easyocr-models`.
- `DEEPFACE_HOME` — `/tmp/deepface-cache`.
- `KERAS_HOME` — `/tmp/keras-cache`.
- `YOLO_CONFIG_DIR` — `/tmp/ultralytics`.
- `TF_USE_LEGACY_KERAS` — `1`.
- `TF_CPP_MIN_LOG_LEVEL` — `2`.
- `TF_NUM_INTRAOP_THREADS` — `1`.
- `TF_NUM_INTEROP_THREADS` — `1`.
- `OMP_NUM_THREADS` — `1`.
- `VERCEL_SUPPORT_LARGE_FUNCTIONS` — `1` (new Vercel projects are generally eligible by default; this explicitly opts this project in where the setting is required).

Never commit `.env` or real credentials.

## First deployment smoke test

After deployment, visit:

`https://YOUR-BACKEND.vercel.app/healthz`

Expected JSON:

```json
{"status":"ok","service":"college-shield-api"}
```

This checks Flask startup only. It does not prove MongoDB connectivity or successful ML inference.

## Vercel Hobby constraints — read before relying on this backend

- Python Functions have a standard 500 MB uncompressed bundle limit. Large Functions can raise this to 5 GB (beta).
- Hobby Functions have 2 GB RAM / 1 vCPU and a 300-second maximum duration.
- The default request-body limit is 4.5 MB. Base64 images should be compressed client-side to stay comfortably below this.
- Function filesystem is read-only except temporary `/tmp` scratch space (up to 500 MB). EasyOCR/DeepFace model caches are therefore temporary and may need to download again after a cold start or new instance.
- TensorFlow + PyTorch + OCR inference may exceed 2 GB RAM or the 5-minute limit on Hobby. If logs show out-of-memory, timeout, or model-load failures, the full inference backend will need a host with more RAM; increasing bundle-size allowance does not increase RAM.
- Hobby is intended for personal, non-commercial projects. Check the current Vercel plan terms before institutional/production use.

## Security before real data

The current API's `/api/auth/sync` flow trusts a role passed in the request. Do not expose real student, visitor, or biometric records until backend-side Clerk token verification and server-side role authorization have been implemented and tested. Frontend-only route guards are not API security.

## Existing project files retained

- `app.py`, `models.py`, `plate_ocr.py`, `face_scanner.py`
- `yolov8n.pt`
- helper modules `config.py` and `database.py`

This repo is prepared for a Vercel deployment attempt; successful deployment and live ML inference must still be verified in the user's Vercel account.
