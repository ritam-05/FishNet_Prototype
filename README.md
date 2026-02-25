# FishNet Android App

FishNet is an on-device Android notification security app. It classifies notifications as useful, ad/promotional, spam, scam, or phishing, and can auto-dismiss unwanted promotional notifications.

## Download APK

- [Download Latest APK](https://github.com/ritam-05/FishNet_Prototype/releases/latest/download/app-release.apk)

## Current App Behavior

- Scans notifications in real time using `NotificationListenerService`.
- Runs startup scans when:
  - listener connects
  - app starts
  - device reboots (if protection is enabled)
- Startup summary now enforces:
  - `useful = scanned - phishing - scam - irrelevant`
  - so every scanned notification is counted.

## Classification Labels

- `SAFE_USEFUL`
- `IRRELEVANT_AD`
- `SPAM`
- `SCAM`
- `PHISHING`

## Blocking Logic

- `IRRELEVANT_AD` notifications can be dismissed based on:
  - auto-block switch
  - per-app policy
  - aggressive mode
- Aggressive mode blocks: `IRRELEVANT_AD`, `SPAM`, `SCAM`, `PHISHING`.
- Flipkart/Amazon notifications are treated with strict promo blocking:
  - non-transactional notifications are force-classified as ad/promotional and removed.
- Other app promotional notifications are also auto-removed when promo signals are present and no transactional signals are found.
- Pre-existing promotional notifications in the tray are also removed during startup scan.
- WhatsApp handling:
  - default path is useful
  - only WhatsApp ad-like messages from unknown numbers are blocked
  - known-contact WhatsApp messages are not blocked by this rule

## Phishing and Scam Alerts

- Phishing alert notification is shown only when phishing risk is `>= 60%`.
- Phishing subtype labels are shown only when risk is `> 50%`.
- Scam detection shows a dedicated scam alert notification.
- Tapping FishNet alerts opens the app.

## Dashboard Metrics

Main dashboard shows:

- notifications scanned today
- phishing today
- scam today
- spam today
- total ads blocked today
- ads blocked today history (dropdown list)
- ad suppression efficiency
- risk meter
- last detected threat

### Ads Blocked Today History

- Every blocked ad is stored temporarily in local storage.
- History retention is 24 hours.
- Old entries are pruned automatically.
- UI count and dropdown list are sourced from the same history store to avoid mismatch.

## ML + Rule Engine

FishNet uses hybrid detection, not ML-only:

1. Extracts signals from text:
- URLs, urgency, action verbs, credential/payment cues

2. Runs deterministic rule engines:
- ad rule engine
- scam logic
- spam frequency/repeat checks
- email-specific threat logic

3. Runs on-device ML scoring:
- ONNX model (`model_int8.onnx`)
- tokenizer (`tokenizer.json`)

4. Combines signals in risk engine:
- ML score + signal strength + domain risk + app/tier context

5. Applies strict final gates:
- phishing requires multiple conditions, not only model score
- subtype and alert visibility are risk-gated

## App Screens

- `MainActivity`: protection toggles + metrics
- `HistoryActivity`: stored scan results
- `SettingsActivity`: aggressive mode, confidence threshold, clear history, export logs

## Boot Behavior

`BootCompletedReceiver` listens to:

- `BOOT_COMPLETED`
- `LOCKED_BOOT_COMPLETED`
- `MY_PACKAGE_REPLACED`

When enabled, it requests notification listener rebind and triggers startup scan.

## Required Permissions

- `android.permission.POST_NOTIFICATIONS`
- `android.permission.READ_CONTACTS`
- `android.permission.RECEIVE_BOOT_COMPLETED`
- notification listener access (user-enabled in system settings)

## Tech Stack

- Kotlin
- Android SDK
- ONNX Runtime
- Room
- Coroutines + StateFlow

## SDK Targets

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

- `android_app/app/build/outputs/apk/release/app-release.apk`
