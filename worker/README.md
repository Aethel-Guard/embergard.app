# embergard.app Worker (Cloudflare)

Cloudflare Worker serving three endpoints for Embergard:

1. **Play Integrity server-side verification** for the Android app.
2. **Stripe Checkout session creation** for the web `Personal` subscription.
3. **Checkout session status** for the `/subscribe/success` confirmation page.

## Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `POST /api/integrity` | POST | Verify Play Integrity token → verdict booleans |
| `POST /api/stripe/checkout` | POST | Create a Checkout Session → `{ url }` |
| `GET /api/stripe/session?id=cs_…` | GET | Session payment status (non-PII fields only) |

POST `/api/stripe/checkout` body:

```json
{ "plan": "monthly" | "yearly" }
```

Error responses use the Stripe-style shape:

```json
{ "error": { "type": "invalid_request_error", "message": "…" } }
```

### Pricing

- Monthly: **€4.99 / month** (`STRIPE_PRICE_MONTHLY` or inline `price_data` fallback)
- Yearly: **€59.00 / year** (`STRIPE_PRICE_YEARLY` or inline `price_data` fallback)

When the optional Price ID vars are unset, the worker creates the subscription
price inline (`price_data`) per request — fine for first runs, but a stable
Price ID is preferred in live mode so dashboard reporting stays tidy.

## Setup

1. Install dependencies (requires network access to npmjs):
   ```bash
   npm install
   npx tsc --noEmit   # typecheck
   ```

2. Google Play service account with the **Play Integrity API** permission and the JSON key.

3. Secrets (never in vars/git):
   ```bash
   npx wrangler secret put GOOGLE_PLAY_SERVICE_ACCOUNT_JSON
   npx wrangler secret put STRIPE_SECRET_KEY        # sk_test_... for testing, sk_live_... for production
   ```

4. Optional vars in `wrangler.toml` once Price objects exist:
   ```toml
   STRIPE_PRICE_MONTHLY = "price_…"
   STRIPE_PRICE_YEARLY  = "price_…"
   ```

5. Create the Price objects once (Stripe Dashboard → Products, pricing €4.99/mo
   and €59.00/yr, currency EUR, recurring) or via the REST API
   (`POST /v1/prices`), then put their IDs into `wrangler.toml`.

6. Deploy:
   ```bash
   npx wrangler deploy
   ```

7. Cloudflare route: `embergard.app/api/*` → this worker (dashboard → Workers
   Routes). The static site (`/`, `/subscribe/`, …) is served separately from
   the repo root; only `/api/*` hits the worker.

## Notes

- Success page `/subscribe/success/?session_id=cs_…` polls `GET /api/stripe/session`
  to confirm `payment_status`, exposing non-PII fields only.
- No PII is logged anywhere in this worker. Session responses strip customer
  details (email, name, address are not included).
- Web-purchase → license-key issuance is planned: the checkout `session_id`
  is kept on the success page as proof of purchase in the interim.
