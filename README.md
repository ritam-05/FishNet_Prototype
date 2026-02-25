# FishNet Android App

FishNet is an on-device Android notification security app. It monitors posted notifications, scores risk, classifies threats, and can auto-dismiss promotional ads.

## Download APK (GitHub Release Link)

- `https://github.com/ritam-05/FishNet_Prototype/releases/latest/download/app-release.apk`

Markdown:

- `[Download Latest APK](https://github.com/ritam-05/FishNet_Prototype/releases/latest/download/app-release.apk)`

## What the App Does

- Scans notifications in real time using a `NotificationListenerService`.
- Runs startup scans when the listener connects or app launches.
- Classifies each notification into:
  - `SAFE_USEFUL`
  - `IRRELEVANT_AD`
  - `SPAM`
  - `SCAM`
  - `PHISHING`
- Tracks dashboard metrics:
  - scanned today
  - phishing/scam/spam/ad counts
  - ad blocking efficiency
  - risk meter + last threat
- Stores history and shows it in `HistoryActivity`.
- Supports feedback overrides and log export from `SettingsActivity`.

## Threat and Risk Behavior

- Risk is computed from multiple signals (ML score + text signals + domain risk + app/tier behavior signals).
- Phishing is emitted only when strict conditions are met (credential/action/route signals + risk threshold).
- Phishing subtype display is risk-gated:
  - `PHISHING_*` subtype appears only when `finalRisk > 0.50`.
- Blocking behavior:
  - High-risk notifications can be blocked (`cancelNotification`) when blocking conditions are met.
  - Ads can be auto-dismissed based on global/per-app policy.

### Risk Meter Function

- The dashboard "Risk Meter" is a daily aggregate meter.
- It is computed from today's counts:
  - `score = (phishingToday * 0.6) + (scamToday * 0.3) + (spamToday * 0.1)`
- Level mapping:
  - `LOW` if score `<= 2`
  - `MEDIUM` if score `<= 5`
  - `HIGH` if score `> 5`
- This meter is count-based for the day; it is not a single-notification ML confidence value.

## ML + Logic Pipeline

FishNet does not rely on ML alone. It uses a layered pipeline where deterministic logic runs before and after model scoring:

1. Signal extraction and context
- Resolve app tier and intent type.
- Extract text/security signals (URL, urgency, action verbs, financial/credential cues).
- Run domain analysis (suspicious TLDs, short links, reputation memory).

2. Rule-first fast paths
- Hard-safe intents short-circuit to `SAFE_USEFUL`.
- Email-specific threat engine can directly resolve safe/ad/phishing-like outcomes.
- Advertisement rules can directly classify `IRRELEVANT_AD` (with phishing-signal exclusion).
- Spam/scam logic can resolve labels before full ML-risk fusion.

3. ML scoring
- ONNX model produces phishing probability from notification text.
- This score is fused with rule/context/domain/app-behavior signals in the risk engine.

4. Final decision logic
- Final risk is calibrated and thresholded by app tier.
- Phishing requires strict multi-condition checks, not just high probability.
- Subtype labeling is post-gated by risk (`PHISHING_*` shown only when `finalRisk > 0.50`).

5. Policy and user feedback layer
- Blocking and protected-mode prompts are applied from final risk/label.
- Ad dismissal policy is applied separately (global + per-app controls).
- User feedback overrides can adjust/replace classification labels.

### How ML Is Used (Implementation Detail)

- Runtime: ONNX Runtime on-device (`model_int8.onnx` in app assets).
- Tokenization: HuggingFace-compatible tokenizer (`tokenizer.json`) with max sequence length `128`.
- Model inputs:
  - `input_ids`
  - `attention_mask`
  - `token_type_ids`
- Model output:
  - `logits` for `4` classes:
    - `0 = SAFE`
    - `1 = EMAIL_PHISHING`
    - `2 = SMS_PHISHING`
    - `3 = URL_PHISHING`
- ML score usage:
  - Softmax confidence is converted to phishing probability.
  - Probability is fused with rule/context/domain/app-memory signals in `RiskEngine`.
  - Final phishing decision still requires rule conditions (ML-only high score is not enough).
- Calibration and guardrails:
  - Confidence thresholding is applied (default model threshold `0.75`).
  - Suspicious URL / SMS / email heuristics can up-rank risk.
  - Casual-benign text guardrail can force safe classification to reduce false positives.
- Fail-safe behavior:
  - If model init/inference fails, FishNet falls back safely and avoids hard-failing the app.

## Ad Blocking

- Ad detection uses keyword/pattern/url/template signals with phishing exclusion logic.
- If classified as `IRRELEVANT_AD`, FishNet checks policy and may dismiss the notification.
- Global auto-dismiss is controlled from the main dashboard switch.
- Per-app ad policy support exists in `PerAppAdControlManager`.

## App Screens

- `MainActivity`
  - protection toggle
  - auto-block ads toggle
  - live security metrics
  - access to history/settings
- `HistoryActivity`
  - list of scanned threat results
- `SettingsActivity`
  - aggressive mode toggle
  - confidence threshold slider
  - clear history
  - export logs as text via share intent

## Startup / Boot Behavior

- `BootCompletedReceiver` listens to:
  - `BOOT_COMPLETED`
  - `LOCKED_BOOT_COMPLETED`
  - `MY_PACKAGE_REPLACED`
- On boot/package update, FishNet:
  - attempts listener rebind
  - triggers startup scan (if protection + notification access are enabled)
  - launches app UI where allowed by OS background launch rules

## Required Permissions

- `android.permission.POST_NOTIFICATIONS`
- `android.permission.READ_CONTACTS`
- `android.permission.RECEIVE_BOOT_COMPLETED`
- notification listener binding via:
  - `android.permission.BIND_NOTIFICATION_LISTENER_SERVICE` (service permission)

## Tech Stack

- Kotlin + Android SDK
- ONNX Runtime (on-device ML inference)
- Room (security/profile data)
- Coroutines + StateFlow

## SDK/Build Targets

- `minSdk = 26`
- `targetSdk = 36`
- `compileSdk = 36`

## Build

From `android_app/`:

```powershell
.\gradlew.bat :app:assembleDebug
```

Release APK:

```powershell
.\gradlew.bat :app:assembleRelease
```

Output:

- `app/build/outputs/apk/release/app-release.apk`
