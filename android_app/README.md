# FishNet Android Security Engine (Version 1 - Baseline)

This document describes the first stable version of FishNet.
It is the baseline before upcoming upgrade iterations.

FishNet uses an offline ELECTRA ONNX text model and wraps it with a context-aware decision layer.
The ML model remains unchanged and receives only notification text.

## Layers

1. `AppTierResolver` (App Context Engine)
- `SYSTEM_APPS`
- `FINANCIAL_TRUSTED`
- `SOCIAL_COMM`
- `UNKNOWN_LOW_TRUST`

2. `RuleEngine` (Rule Analysis)
- `hasUrl`
- `urgencyScore`
- `numericDensity`
- `otpPattern`
- `transactionPattern`
- `adPattern`

3. `RiskScorer` (Risk Matrix)
- Base risk = `phishing_probability`
- Applies tier/rule modifiers
- Caps final risk to `[0, 1]`

4. `FinalDecisionEngine` (Final Labeling)
- `SAFE_USEFUL`
- `IRRELEVANT_AD`
- `PHISHING_KYC`
- `PHISHING_PAYMENT`
- `PHISHING_LOGIN`
- `PHISHING_GENERAL`

5. Confidence Calibration
- `< 0.30` => `Low Risk`
- `0.30 - 0.60` => `Moderate Risk`
- `0.60 - 0.80` => `High Risk`
- `> 0.80` => `Critical Risk`

## Integration API

`HybridDecisionEngine.processNotification(text: String, packageName: String): FinalResult`

`FinalResult` includes:
- `finalLabel`
- `calibratedRisk`
- `confidenceLevel`
- `appTier`

## Storage Categories

App history stores user-facing categories:
- `PHISHING`
- `USEFUL`
- `IRRELEVANT`

For phishing entries, subtype is stored separately.

## Versioning Note

- This README is for `v1` behavior and architecture.
- Next upgrades will be added incrementally on top of this baseline.
- When upgrading, keep backward compatibility for labels and stored categories unless migration is explicitly introduced.
