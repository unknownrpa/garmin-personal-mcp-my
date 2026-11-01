/**
 * A single-user OAuth 2.1 authorization server, so that clients which can only
 * sign in through OAuth (Claude on the web and mobile, ChatGPT) can reach this server.
 *
 * There is one person and no database. Sign-in is one password, and everything a
 * normal server would store (clients, codes, tokens) is a signed value handed to the
 * client. That keeps HTTP mode stateless, with three consequences worth knowing:
 *
 * - A code cannot be marked as used. It lives for 60 seconds and is useless without
 *   the PKCE verifier, which stands in for single use.
 * - A refresh token is replaced on every refresh, but the old one stays valid until it
 *   expires.
 * - Nothing can be revoked individually. Changing OAUTH_SIGNING_KEY revokes everything.
 *
 * Client ID Metadata Documents are deliberately not advertised: supporting them means
 * fetching URLs the client names. Claude and ChatGPT both fall back to registration.
 */
import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface OAuthConfig {
  /** Origin clients reach this server on, e.g. https://you.vercel.app. */
  publicUrl: string;
  /** The sign-in password. It is the only thing between the internet and your health data. */
  password: string;
  /** HMAC key for everything issued here. Changing it signs every client out. */
  signingKey: string;
  /** Seconds since the epoch. */
  now?: () => number;
}

export interface OAuthServer {
  /** Answers the OAuth endpoints; null for any other path. */
  handle(request: Request, pathname: string): Promise<Response | null>;
  accepts(token: string): boolean;
  /** Value of WWW-Authenticate on a 401 from the MCP endpoint. */
  challenge: string;
}

const MIN_SECRET_LENGTH = 32;
const CODE_SECONDS = 60;
const ACCESS_SECONDS = 60 * 60;
const REFRESH_SECONDS = 30 * 24 * 60 * 60;

const RESOURCE_SCOPE = "garmin:read";
const OFFLINE_SCOPE = "offline_access";

const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server";

const HOSTED_REDIRECTS = new Set(["https://claude.ai/api/mcp/auth_callback", "https://chatgpt.com/connector_platform_oauth_redirect"]);
const CHATGPT_CALLBACK_REDIRECT = /^https:\/\/chatgpt\.com\/connector\/oauth\/[\w-]+$/;
const LOOPBACK_REDIRECT = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?\/callback$/;

/** The hidden fields of the sign-in form, which are exactly the authorization request. */
const AUTHORIZE_FIELDS = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource"] as const;

type AuthorizeField = (typeof AUTHORIZE_FIELDS)[number];
type AuthorizeRequest = Partial<Record<AuthorizeField, string>>;
type TokenKind = "client" | "code" | "access" | "refresh";
type Claims = Record<string, unknown>;

const isAllowedRedirect = (uri: unknown): uri is string =>
  typeof uri === "string" && (HOSTED_REDIRECTS.has(uri) || CHATGPT_CALLBACK_REDIRECT.test(uri) || LOOPBACK_REDIRECT.test(uri));

/** RFC 8252: a native client picks its port per session, so the port is not part of the match. */
function matchesRegistered(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true;
  const withoutPort = (u: string) => u.replace(/:\d+(?=\/)/, "");
  return LOOPBACK_REDIRECT.test(uri) && registered.some((r) => LOOPBACK_REDIRECT.test(r) && withoutPort(r) === withoutPort(uri));
}

function canonicalPublicUrl(publicUrl: string): string {
  let url: URL;
  try {
    url = new URL(publicUrl);
  } catch {
    throw new Error(`MCP_PUBLIC_URL is not a URL: ${publicUrl}`);
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) throw new Error("MCP_PUBLIC_URL must use https");
  if (url.pathname !== "/" || url.search || url.hash) throw new Error("MCP_PUBLIC_URL must be an origin, with no path");
  return url.origin;
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

const json = (body: unknown, status = 200) => Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
const oauthError = (error: string, status = 400) => json({ error }, status);
const methodNotAllowed = () => new Response("Method not allowed", { status: 405 });

function page(request: AuthorizeRequest, wrongPassword: boolean): Response {
  const { hostname } = new URL(request.redirect_uri!);
  const local = LOOPBACK_REDIRECT.test(request.redirect_uri!);
  const fields = AUTHORIZE_FIELDS.map((name) => `<input type="hidden" name="${name}" value="${escapeHtml(request[name] ?? "")}">`).join("");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connect Garmin</title>
<style>
:root { color-scheme: light dark; }
body { font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 15vh auto; padding: 0 1rem; }
input[type=password], button { box-sizing: border-box; width: 100%; padding: .6rem; font: inherit; margin-top: .5rem; }
.warn { font-weight: 600; }
</style>
</head>
<body>
<h1>Connect Garmin</h1>
<p>Sign in to give <strong>${escapeHtml(hostname)}</strong> read access to your Garmin data.</p>
${local ? "<p class=\"warn\">This sends access to a local program on this computer. Continue only if you started the connection yourself.</p>" : ""}
${wrongPassword ? "<p class=\"warn\" role=\"alert\">Wrong password.</p>" : ""}
<form method="post" action="/authorize">
${fields}
<label>Password <input type="password" name="password" autocomplete="current-password" required autofocus></label>
<button type="submit">Allow</button>
</form>
</body>
</html>`;
  return new Response(html, {
    status: wrongPassword ? 401 : 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      // No form-action: Chrome applies it to the redirect after submit, which would block the return to the client.
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    },
  });
}

export function createOAuth(config: OAuthConfig, mcpPath = "/mcp"): OAuthServer {
  if (config.password.length < MIN_SECRET_LENGTH) throw new Error(`OAUTH_PASSWORD must be at least ${MIN_SECRET_LENGTH} characters`);
  if (config.signingKey.length < MIN_SECRET_LENGTH) throw new Error(`OAUTH_SIGNING_KEY must be at least ${MIN_SECRET_LENGTH} characters`);
  const issuer = canonicalPublicUrl(config.publicUrl);
  const resource = `${issuer}${mcpPath}`;
  const now = () => Math.floor(config.now?.() ?? Date.now() / 1000);
  const signature = (payload: string) => createHmac("sha256", config.signingKey).update(payload).digest();

  function sign(typ: TokenKind, claims: Claims, ttl?: number): string {
    const body: Claims = { ...claims, typ, iss: issuer };
    if (ttl !== undefined) body.exp = now() + ttl;
    const payload = Buffer.from(JSON.stringify(body)).toString("base64url");
    return `${payload}.${signature(payload).toString("base64url")}`;
  }

  function verify(token: unknown, typ: TokenKind): Claims | null {
    if (typeof token !== "string") return null;
    const [payload, given, ...rest] = token.split(".");
    if (!payload || !given || rest.length) return null;
    const expected = signature(payload);
    const actual = Buffer.from(given, "base64url");
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as Claims;
    if (claims.typ !== typ || claims.iss !== issuer) return null;
    if (typeof claims.exp === "number" && now() > claims.exp) return null;
    return claims;
  }

  function passwordMatches(given: string): boolean {
    const hash = (value: string) => createHash("sha256").update(value).digest();
    return timingSafeEqual(hash(given), hash(config.password));
  }

  const sameResource = (value: string) => {
    try {
      return new URL(value).href.replace(/\/$/, "") === resource;
    } catch {
      return false;
    }
  };

  function issueTokens(clientId: string, scope: string) {
    const claims = { aud: resource, scope, client_id: clientId, jti: randomBytes(16).toString("base64url") };
    return json({
      access_token: sign("access", claims, ACCESS_SECONDS),
      refresh_token: sign("refresh", claims, REFRESH_SECONDS),
      token_type: "Bearer",
      expires_in: ACCESS_SECONDS,
      scope,
    });
  }

  function redirectBack(redirectUri: string, state: string | undefined, params: Record<string, string>): Response {
    const url = new URL(redirectUri);
    for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
    if (state) url.searchParams.set("state", state);
    url.searchParams.set("iss", issuer);
    return new Response(null, { status: 302, headers: { Location: url.href, "Cache-Control": "no-store" } });
  }

  /** The checks behind GET and POST alike: the form's hidden fields come back from the client. */
  function checkAuthorize(request: AuthorizeRequest): { response: Response } | { scope: string } {
    const client = verify(request.client_id, "client");
    const redirectUri = request.redirect_uri;
    // Until both of these hold there is nowhere safe to redirect to.
    if (!client) return { response: new Response("Unknown client", { status: 400 }) };
    if (!redirectUri || !matchesRegistered(client.redirect_uris as string[], redirectUri)) {
      return { response: new Response("This redirect_uri is not registered for this client", { status: 400 }) };
    }
    const refuse = (error: string) => ({ response: redirectBack(redirectUri, request.state, { error }) });
    if (request.response_type !== "code") return refuse("unsupported_response_type");
    if (!request.code_challenge || request.code_challenge_method !== "S256") return refuse("invalid_request");
    if (request.resource && !sameResource(request.resource)) return refuse("invalid_target");
    const requested = request.scope?.split(" ").filter(Boolean) ?? [];
    if (requested.length && !requested.some((s) => s === RESOURCE_SCOPE || s === OFFLINE_SCOPE)) return refuse("invalid_scope");
    return { scope: RESOURCE_SCOPE };
  }

  async function authorize(request: Request): Promise<Response> {
    if (request.method !== "GET" && request.method !== "POST") return methodNotAllowed();
    const submitted = request.method === "POST" ? await request.formData().catch(() => new FormData()) : null;
    const read = (name: string) => {
      const value = submitted ? submitted.get(name) : new URL(request.url).searchParams.get(name);
      return typeof value === "string" ? value : undefined;
    };
    const fields: AuthorizeRequest = Object.fromEntries(AUTHORIZE_FIELDS.map((name) => [name, read(name)]));
    const checked = checkAuthorize(fields);
    if ("response" in checked) return checked.response;
    if (!submitted) return page(fields, false);
    if (!passwordMatches(read("password") ?? "")) return page(fields, true);
    const code = sign(
      "code",
      { client_id: fields.client_id, redirect_uri: fields.redirect_uri, code_challenge: fields.code_challenge, aud: resource, scope: checked.scope },
      CODE_SECONDS,
    );
    return redirectBack(fields.redirect_uri!, fields.state, { code });
  }

  async function token(request: Request): Promise<Response> {
    if (request.method !== "POST") return methodNotAllowed();
    if (!request.headers.get("content-type")?.startsWith("application/x-www-form-urlencoded")) return oauthError("invalid_request");
    const form = new URLSearchParams(await request.text());
    const grant = form.get("grant_type");
    if (grant !== "authorization_code" && grant !== "refresh_token") return oauthError("unsupported_grant_type");
    const clientId = form.get("client_id") ?? "";
    if (!verify(clientId, "client")) return oauthError("invalid_client", 401);
    const requested = form.get("resource");
    if (requested && !sameResource(requested)) return oauthError("invalid_grant");

    if (grant === "refresh_token") {
      const claims = verify(form.get("refresh_token"), "refresh");
      if (!claims || claims.client_id !== clientId) return oauthError("invalid_grant");
      return issueTokens(clientId, claims.scope as string);
    }

    const claims = verify(form.get("code"), "code");
    const verifier = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
    if (!claims || claims.client_id !== clientId || claims.redirect_uri !== form.get("redirect_uri") || claims.code_challenge !== verifier) {
      return oauthError("invalid_grant");
    }
    return issueTokens(clientId, claims.scope as string);
  }

  async function register(request: Request): Promise<Response> {
    if (request.method !== "POST") return methodNotAllowed();
    const body = (await request.json().catch(() => null)) as { redirect_uris?: unknown } | null;
    if (!body || typeof body !== "object") return oauthError("invalid_client_metadata");
    const uris = body.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || !uris.every(isAllowedRedirect)) return oauthError("invalid_redirect_uri");
    return json(
      {
        client_id: sign("client", { redirect_uris: uris }),
        client_id_issued_at: now(),
        redirect_uris: uris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
      201,
    );
  }

  const metadata = (body: unknown) => async (request: Request) => (request.method === "GET" ? json(body) : methodNotAllowed());

  const protectedResource = metadata({
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: [RESOURCE_SCOPE],
  });

  const routes: Record<string, (request: Request) => Promise<Response>> = {
    [PROTECTED_RESOURCE_PATH]: protectedResource,
    [`${PROTECTED_RESOURCE_PATH}${mcpPath}`]: protectedResource,
    [AUTHORIZATION_SERVER_PATH]: metadata({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: [RESOURCE_SCOPE, OFFLINE_SCOPE],
      authorization_response_iss_parameter_supported: true,
    }),
    "/authorize": authorize,
    "/token": token,
    "/register": register,
  };

  return {
    handle: async (request, pathname) => (Object.hasOwn(routes, pathname) ? routes[pathname](request) : null),
    accepts(presented) {
      const claims = verify(presented, "access");
      return claims?.aud === resource && claims.scope === RESOURCE_SCOPE;
    },
    challenge: `Bearer resource_metadata="${issuer}${PROTECTED_RESOURCE_PATH}", scope="${RESOURCE_SCOPE}"`,
  };
}

/** OAuth is all or nothing: half a setup must fail loudly, not quietly fall back to no sign-in. */
export function oauthConfigFromEnv(env: Record<string, string | undefined> = process.env): OAuthConfig | undefined {
  const names = ["MCP_PUBLIC_URL", "OAUTH_PASSWORD", "OAUTH_SIGNING_KEY"] as const;
  const [publicUrl, password, signingKey] = names.map((name) => env[name]?.trim());
  if (!publicUrl && !password && !signingKey) return undefined;
  if (!publicUrl || !password || !signingKey) {
    const missing = names.filter((name) => !env[name]?.trim());
    throw new Error(`OAuth needs all of ${names.join(", ")}; missing ${missing.join(", ")}`);
  }
  return { publicUrl, password, signingKey };
}
