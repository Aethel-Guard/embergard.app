/**
 * Cloudflare Worker — Embergard API gateway.
 *
 * Endpoints:
 *   POST https://embergard.app/api/integrity
 *     Play Integrity token verification. Body: { token, requestHash? }
 *     → { healthy, playRecognized, meetsDeviceIntegrity, meetsBasicIntegrity, licensed }
 *
 *   POST https://embergard.app/api/stripe/checkout
 *     Create a Stripe Checkout Session for Embergard Personal. Body: { plan: "monthly" | "yearly" }
 *     → { url: "<stripe checkout url>" }
 *     Requires STRIPE_SECRET_KEY secret. Uses STRIPE_PRICE_MONTHLY / STRIPE_PRICE_YEARLY
 *     vars when set; otherwise falls back to inline price_data (EUR 4.99 / 59.00).
 *
 *   GET https://embergard.app/api/stripe/session?id=cs_xxx
 *     Retrieve a Checkout Session's payment status for the success page.
 *     → { id, status, payment_status, amount_total, currency, mode }
 *
 * Error shape (Stripe-style): { error: { type, message } }
 *
 * Secrets & vars — see wrangler.toml and README.md.
 * P1 redline: No PII is logged. Checkout/session responses expose no customer details.
 */

export interface Env {
  // Play Integrity
  GOOGLE_CLOUD_PROJECT_NUMBER: string;
  PACKAGE_NAME: string;
  GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: string;
  // Stripe
  STRIPE_SECRET_KEY?: string;
  SITE_URL?: string;
  STRIPE_PRICE_MONTHLY?: string;
  STRIPE_PRICE_YEARLY?: string;
}

interface IntegrityRequest {
  token?: string;
  requestHash?: string;
}

interface ServiceAccount {
  type: string;
  client_email: string;
  private_key: string;
  token_uri: string;
}

interface GoogleTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

interface IntegrityVerdict {
  requestDetails?: {
    requestPackageName?: string;
    timestampMillis?: string;
    nonce?: string;
  };
  appIntegrity?: {
    appRecognitionVerdict?: string;
    packageName?: string;
    certificateSha256Digest?: string[];
    versionCode?: string;
  };
  deviceIntegrity?: {
    deviceRecognitionVerdict?: string[];
  };
  accountDetails?: {
    appLicensingVerdict?: string;
  };
}

interface StripeCheckoutSession {
  id: string;
  object: "checkout.session";
  url: string | null;
  status?: string;
  payment_status?: string;
  amount_total?: number;
  currency?: string;
  mode?: string;
}

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const PLAN_CONFIG = {
  monthly: {
    priceIdVar: "STRIPE_PRICE_MONTHLY",
    productName: "Embergard Personal — Monthly",
    interval: "month" as const,
    unitAmount: 499,
  },
  yearly: {
    priceIdVar: "STRIPE_PRICE_YEARLY",
    productName: "Embergard Personal — Yearly",
    interval: "year" as const,
    unitAmount: 5900,
  },
};

type PlanKey = keyof typeof PLAN_CONFIG;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");

    try {
      switch (path) {
        case "/api/integrity":
          return handleIntegrity(request, env);
        case "/api/stripe/checkout":
          return handleStripeCheckout(request, env);
        case "/api/stripe/session":
          return handleStripeSession(request, url, env);
        default:
          return jsonResponse(
            { error: { type: "invalid_request_error", message: "Not found" } },
            404
          );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Internal error";
      return jsonResponse(
        { error: { type: "api_error", message } },
        500
      );
    }
  },
};

// ── Play Integrity (unchanged behaviour) ─────────────────────────────

async function handleIntegrity(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Method not allowed" } },
      405
    );
  }

  let body: IntegrityRequest;
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Invalid JSON body" } },
      400
    );
  }

  const token = body.token;
  if (!token || typeof token !== "string") {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Missing 'token' field" } },
      400
    );
  }

  const verdict = await decodeIntegrityToken(token, env);
  const result = evaluateVerdict(verdict, env.PACKAGE_NAME);
  return jsonResponse(result, 200);
}

function evaluateVerdict(verdict: IntegrityVerdict, expectedPackageName: string): {
  healthy: boolean;
  playRecognized: boolean;
  meetsDeviceIntegrity: boolean;
  meetsBasicIntegrity: boolean;
  licensed: boolean;
} {
  const appRecognition = verdict.appIntegrity?.appRecognitionVerdict ?? "";
  const deviceRecognition = verdict.deviceIntegrity?.deviceRecognitionVerdict ?? [];
  const licenseVerdict = verdict.accountDetails?.appLicensingVerdict ?? "";
  const packageName = verdict.requestDetails?.requestPackageName ?? "";

  const playRecognized = appRecognition === "PLAY_RECOGNIZED" || appRecognition === "PLAY_RECOGNIZED_Genuine";
  const meetsDeviceIntegrity = deviceRecognition.includes("MEETS_DEVICE_INTEGRITY");
  const meetsBasicIntegrity = deviceRecognition.includes("MEETS_BASIC_INTEGRITY");
  const licensed = licenseVerdict === "LICENSED";
  const packageMatch = !expectedPackageName || packageName === expectedPackageName;

  return {
    healthy: playRecognized && meetsDeviceIntegrity && licensed && packageMatch,
    playRecognized,
    meetsDeviceIntegrity,
    meetsBasicIntegrity,
    licensed,
  };
}

async function decodeIntegrityToken(
  token: string,
  env: Env
): Promise<IntegrityVerdict> {
  const sa = parseServiceAccount(env.GOOGLE_PLAY_SERVICE_ACCOUNT_JSON);
  const accessToken = await getGoogleAccessToken(sa);

  const url =
    "https://playintegrity.googleapis.com/v1/" +
    `${encodeURIComponent(env.PACKAGE_NAME)}:decodeIntegrityToken`;

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ integrity_token: token }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Google Play Integrity API error ${response.status}: ${text}`);
  }

  return (await response.json()) as IntegrityVerdict;
}

function parseServiceAccount(json: string): ServiceAccount {
  try {
    const sa = JSON.parse(json) as Partial<ServiceAccount>;
    if (!sa.client_email || !sa.private_key || !sa.token_uri) {
      throw new Error("Service account JSON is missing required fields");
    }
    return sa as ServiceAccount;
  } catch {
    throw new Error("GOOGLE_PLAY_SERVICE_ACCOUNT_JSON is invalid");
  }
}

async function getGoogleAccessToken(sa: ServiceAccount): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwtHeader = base64UrlEncode(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const jwtClaimSet = base64UrlEncode(
    JSON.stringify({
      iss: sa.client_email,
      scope: "https://www.googleapis.com/auth/playintegrity",
      aud: sa.token_uri,
      exp: now + 3600,
      iat: now,
    })
  );
  const signingInput = `${jwtHeader}.${jwtClaimSet}`;
  const signature = await signRs256(signingInput, sa.private_key);
  return [
    base64UrlEncode(jwtHeader),
    base64UrlEncode(jwtClaimSet),
    base64UrlEncode(new Uint8Array(signature)),
  ].join(".");
}

async function signRs256(input: string, pem: string): Promise<ArrayBuffer> {
  const keyData = parsePem(pem);
  const key = await crypto.subtle.importKey(
    "pkcs8",
    keyData,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(input)
  );
  return sig;
}

function parsePem(pem: string): ArrayBuffer {
  const b64 = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s+/g, "");
  const raw = atob(b64);
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes.buffer as ArrayBuffer;
}

function base64UrlEncode(input: string | Uint8Array): string {
  const b64 =
    typeof input === "string"
      ? btoa(String.fromCharCode(...new TextEncoder().encode(input)))
      : btoa(String.fromCharCode(...input));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Stripe Checkout ──────────────────────────────────────────────────

function siteUrl(env: Env): string {
  return (env.SITE_URL || "https://embergard.app").replace(/\/+$/, "");
}

async function handleStripeCheckout(request: Request, env: Env): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Method not allowed" } },
      405
    );
  }
  if (!env.STRIPE_SECRET_KEY) {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "STRIPE_SECRET_KEY is not configured" } },
      500
    );
  }

  let body: { plan?: string; email?: string };
  try {
    body = await request.json();
  } catch {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Invalid JSON body" } },
      400
    );
  }

  const plan = (body.plan || "").toLowerCase() as PlanKey;
  if (!(plan in PLAN_CONFIG)) {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Missing or invalid 'plan' — expected \"monthly\" or \"yearly\"" } },
      400
    );
  }

  const cfg = PLAN_CONFIG[plan];
  const site = siteUrl(env);

  // Form-encoded POST per the Stripe REST API reference.
  const form = new URLSearchParams();
  form.set("mode", "subscription");
  form.set("success_url", `${site}/subscribe/success/?session_id={CHECKOUT_SESSION_ID}`);
  form.set("cancel_url", `${site}/subscribe/`);

  if (env[cfg.priceIdVar as keyof Env]) {
    // Use a stable Price object when one is configured.
    form.set("line_items[0][quantity]", "1");
    form.set("line_items[0][price]", env[cfg.priceIdVar as keyof Env] as string);
  } else {
    // Fallback: inline price_data so checkout works before Price IDs are created.
    form.set("line_items[0][quantity]", "1");
    form.set("line_items[0][price_data][currency]", "eur");
    form.set("line_items[0][price_data][unit_amount]", String(cfg.unitAmount));
    form.set("line_items[0][price_data][recurring][interval]", cfg.interval);
    form.set("line_items[0][price_data][product_data][name]", cfg.productName);
  }

  const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });

  const session = (await response.json()) as StripeCheckoutSession & {
    error?: { type?: string; message?: string };
  };

  if (!response.ok) {
    const type = session.error?.type ?? "api_error";
    const message = session.error?.message ?? `Stripe API error ${response.status}`;
    return jsonResponse({ error: { type, message } }, response.status >= 500 ? 502 : 400);
  }

  if (!session.url) {
    return jsonResponse(
      { error: { type: "api_error", message: "Stripe returned no checkout URL" } },
      502
    );
  }

  return jsonResponse({ url: session.url }, 200);
}

async function handleStripeSession(request: Request, url: URL, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Method not allowed" } },
      405
    );
  }
  const sessionParam = url.searchParams.get("id");
  if (!sessionParam || !/^cs_(test|live)_[A-Za-z0-9]+$/.test(sessionParam)) {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "Missing or invalid 'id' query parameter" } },
      400
    );
  }
  if (!env.STRIPE_SECRET_KEY) {
    return jsonResponse(
      { error: { type: "invalid_request_error", message: "STRIPE_SECRET_KEY is not configured" } },
      500
    );
  }

  const response = await fetch(`https://api.stripe.com/v1/checkout/sessions/${sessionParam}`, {
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  });

  const session = (await response.json()) as StripeCheckoutSession & {
    error?: { type?: string; message?: string };
  };

  if (!response.ok) {
    const type = session.error?.type ?? "api_error";
    const message = session.error?.message ?? `Stripe API error ${response.status}`;
    return jsonResponse({ error: { type, message } }, response.status >= 500 ? 502 : 400);
  }

  // Strip to non-PII fields only.
  return jsonResponse(
    {
      id: session.id,
      status: session.status ?? null,
      payment_status: session.payment_status ?? null,
      amount_total: session.amount_total ?? null,
      currency: session.currency ?? null,
      mode: session.mode ?? null,
    },
    200
  );
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: CORS_HEADERS,
  });
}
