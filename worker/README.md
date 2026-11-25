# embergard.app Play Integrity Worker

Cloudflare Worker that verifies Google Play Integrity tokens server-side for the Embergard Android app.

## Endpoint

```
POST https://embergard.app/api/integrity
```

## Request body

```json
{
  "token": "<base64 Play Integrity token>",
  "requestHash": "<optional SHA-256 of the in-app request>"
}
```

## Response

```json
{
  "healthy": true,
  "playRecognized": true,
  "meetsDeviceIntegrity": true,
  "meetsBasicIntegrity": true,
  "licensed": true
}
```

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a Google Cloud service account with the **Play Integrity API** permission and download the JSON key.

3. Add the secret to Cloudflare:
   ```bash
   npx wrangler secret put GOOGLE_PLAY_SERVICE_ACCOUNT_JSON
   # paste the JSON key contents
   ```

4. Deploy:
   ```bash
   npm run deploy
   ```

5. Add a Cloudflare route mapping `embergard.app/api/integrity*` to this worker.

## Notes

- PII is never logged.
- The worker only returns verdict booleans.
- Requires Wrangler login (`npx wrangler login`).
