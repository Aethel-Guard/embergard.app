/**
 * Cloudflare Worker — Play Integrity server-side verifier.
 *
 * Endpoint: POST https://embergard.app/api/integrity
 *
 * Body (JSON):
 *   {
 *     "token": "<base64-encoded Play Integrity token>",
 *     "requestHash": "<optional SHA-256 of the in-app request>"
 *   }
 *
 * Response (JSON):
 *   {
 *     "healthy": true,
 *     "playRecognized": true,
 *     "meetsDeviceIntegrity": true,
 *     "meetsBasicIntegrity": true,
 *     "licensed": true
 *   }
 *
 * Environment:
 *   - GOOGLE_CLOUD_PROJECT_NUMBER: 378810733196
 *   - PACKAGE_NAME: com.embergard.app
 *   - GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: service-account key JSON
 *
 * P1 redline: No PII is logged. Only verdict booleans and request hashes are returned.
 */

export interface Env {
  GOOGLE_CLOUD_PROJECT_NUMBER: string;
  PACKAGE_NAME: string;
  GOOGLE_PLAY_SERVICE_ACCOUNT_JSON: string;
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

const CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== "POST") {
      return jsonResponse({ error: "Method not allowed" }, 405);
    }

    let body: IntegrityRequest;
    try {
      body = await request.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }

    const token = body.token;
    if (!token || typeof token !== "string") {
      return jsonResponse({ error: "Missing 'token' field" }, 400);
    }

    try {
      const verdict = await decodeIntegrityToken(token, env);
      const result = evaluateVerdict(verdict, env.PACKAGE_NAME);
      return jsonResponse(result, 200);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Token verification failed";
      return jsonResponse({ error: message }, 500);
    }
  },
};

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: CORS_HEADERS,
  });
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
  const jwt = `${signingInput}.${signature}`;

  const tokenResponse = await fetch(sa.token_uri, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  if (!tokenResponse.ok) {
    const text = await tokenResponse.text();
    throw new Error(`Google OAuth error ${tokenResponse.status}: ${text}`);
  }

  const data = (await tokenResponse.json()) as GoogleTokenResponse;
  return data.access_token;
}

async function signRs256(input: string, privateKeyPem: string): Promise<string> {
  const pem = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");
  const keyData = base64ToUint8Array(pem);

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyData.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    cryptoKey,
    encoder.encode(input)
  );

  return base64UrlEncodeBytes(new Uint8Array(signature));
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlEncode(input: string): string {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
