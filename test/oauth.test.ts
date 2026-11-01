import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it } from "vitest";
import { createFetchHandler } from "../src/http.js";
import { oauthConfigFromEnv, type OAuthConfig } from "../src/oauth.js";

const PUBLIC = "https://mcp.example.test";
const RESOURCE = `${PUBLIC}/mcp`;
const CLAUDE = "https://claude.ai/api/mcp/auth_callback";
const CHATGPT = "https://chatgpt.com/connector_platform_oauth_redirect";
const PASSWORD = "correct-horse-battery-staple-0123456789";
const SIGNING_KEY = "signing-key-signing-key-signing-key-0123";
const STATIC = "static-bearer-token";
const VERIFIER = "a-sufficiently-long-pkce-code-verifier-0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

let clock = 1_000_000;

type Handler = (r: Request) => Promise<Response>;

function setup(over: Partial<OAuthConfig> = {}): Handler {
  return createFetchHandler({
    apiKey: "k",
    bearerToken: STATIC,
    oauth: { publicUrl: PUBLIC, password: PASSWORD, signingKey: SIGNING_KEY, now: () => clock, ...over },
  });
}

const get = (h: Handler, path: string) => h(new Request(`${PUBLIC}${path}`));

const form = (h: Handler, path: string, fields: Record<string, string>) =>
  h(
    new Request(`${PUBLIC}${path}`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(fields).toString(),
    }),
  );

async function register(h: Handler, redirect_uris: unknown = [CLAUDE]) {
  return h(
    new Request(`${PUBLIC}/register`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ redirect_uris, client_name: "Test client", token_endpoint_auth_method: "none" }),
    }),
  );
}

async function clientId(h: Handler, uri = CLAUDE) {
  const res = await register(h, [uri]);
  return ((await res.json()) as { client_id: string }).client_id;
}

const authFields = (client_id: string, over: Record<string, string> = {}) => ({
  response_type: "code",
  client_id,
  redirect_uri: CLAUDE,
  code_challenge: CHALLENGE,
  code_challenge_method: "S256",
  state: "state-123",
  scope: "garmin:read offline_access",
  resource: RESOURCE,
  ...over,
});

const authQuery = (fields: Record<string, string>) => `/authorize?${new URLSearchParams(fields)}`;

async function issueCode(h: Handler, client_id: string, over: Record<string, string> = {}) {
  const res = await form(h, "/authorize", { ...authFields(client_id, over), password: PASSWORD });
  expect(res.status).toBe(302);
  return new URL(res.headers.get("location")!).searchParams.get("code")!;
}

const exchange = (h: Handler, client_id: string, code: string, over: Record<string, string> = {}) =>
  form(h, "/token", {
    grant_type: "authorization_code",
    code,
    client_id,
    redirect_uri: CLAUDE,
    code_verifier: VERIFIER,
    resource: RESOURCE,
    ...over,
  });

const refresh = (h: Handler, client_id: string, refresh_token: string, over: Record<string, string> = {}) =>
  form(h, "/token", { grant_type: "refresh_token", refresh_token, client_id, resource: RESOURCE, ...over });

interface Tokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

async function tokens(h: Handler, client_id: string): Promise<Tokens> {
  const res = await exchange(h, client_id, await issueCode(h, client_id));
  expect(res.status).toBe(200);
  return (await res.json()) as Tokens;
}

const mcp = (h: Handler, token?: string) =>
  h(
    new Request(RESOURCE, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
    }),
  );

const errorOf = async (res: Response) => ((await res.json()) as { error: string }).error;

beforeEach(() => {
  clock = 1_000_000;
});

describe("discovery", () => {
  it("publishes protected resource metadata at the root and at the path-suffixed location", async () => {
    const h = setup();
    for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
      const res = await get(h, path);
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body.resource).toBe(RESOURCE);
      expect(body.authorization_servers).toEqual([PUBLIC]);
      expect(body.bearer_methods_supported).toEqual(["header"]);
      // The MCP spec: offline_access is not a resource requirement.
      expect(body.scopes_supported).toEqual(["garmin:read"]);
    }
  });

  it("publishes authorization server metadata that Claude and ChatGPT accept", async () => {
    const res = await get(setup(), "/.well-known/oauth-authorization-server");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      issuer: PUBLIC,
      authorization_endpoint: `${PUBLIC}/authorize`,
      token_endpoint: `${PUBLIC}/token`,
      registration_endpoint: `${PUBLIC}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["garmin:read", "offline_access"],
      authorization_response_iss_parameter_supported: true,
    });
  });

  it("answers an unauthenticated MCP call with a 401 that points at the metadata", async () => {
    const res = await mcp(setup());
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource", scope="garmin:read"`,
    );
  });

  it("uses the same challenge for a token it does not recognise", async () => {
    const res = await mcp(setup(), "nope");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toContain("resource_metadata=");
  });

  it("stays off when OAuth is not configured", async () => {
    const h = createFetchHandler({ apiKey: "k", bearerToken: STATIC });
    expect((await get(h, "/.well-known/oauth-protected-resource")).status).toBe(404);
    expect((await get(h, "/.well-known/oauth-authorization-server")).status).toBe(404);
    expect((await form(h, "/token", {})).status).toBe(404);
    expect((await mcp(h)).headers.get("www-authenticate")).toBe("Bearer");
  });
});

describe("client registration", () => {
  it.each([
    ["Claude", CLAUDE],
    ["ChatGPT with RFC 9207", CHATGPT],
    ["ChatGPT with a callback id", "https://chatgpt.com/connector/oauth/abc_123-XYZ"],
    ["Claude Code on localhost", "http://localhost:3118/callback"],
    ["Claude Code on 127.0.0.1", "http://127.0.0.1:49152/callback"],
    ["a loopback redirect with no port", "http://localhost/callback"],
  ])("registers %s as a public client", async (_name, uri) => {
    const res = await register(setup(), [uri]);
    expect(res.status).toBe(201);
    const body = (await res.json()) as Record<string, unknown>;
    expect(typeof body.client_id).toBe("string");
    expect(body.redirect_uris).toEqual([uri]);
    expect(body.token_endpoint_auth_method).toBe("none");
    expect(body.client_secret).toBeUndefined();
  });

  it.each([
    ["an arbitrary site", "https://evil.example/callback"],
    ["a lookalike host", "https://claude.ai.evil.example/api/mcp/auth_callback"],
    ["userinfo before the real host", "https://claude.ai@evil.example/api/mcp/auth_callback"],
    ["another path on claude.ai", "https://claude.ai/api/mcp/other"],
    ["a query on the exact URL", `${CLAUDE}?x=1`],
    ["plain http on claude.ai", "http://claude.ai/api/mcp/auth_callback"],
    ["a callback id with a slash", "https://chatgpt.com/connector/oauth/a/b"],
    ["a loopback lookalike", "http://localhost.evil.example/callback"],
    ["another loopback path", "http://localhost:3118/other"],
    ["https on loopback", "https://localhost:3118/callback"],
    ["a custom scheme", "javascript:alert(1)"],
    ["not a URL", "nope"],
  ])("refuses %s", async (_name, uri) => {
    const res = await register(setup(), [uri]);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_redirect_uri");
  });

  it("refuses a list where any one redirect is foreign", async () => {
    expect((await register(setup(), [CLAUDE, "https://evil.example/cb"])).status).toBe(400);
  });

  it.each([[[]], ["not-a-list"], [null]])("refuses redirect_uris=%j", async (value) => {
    const res = await register(setup(), value);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_redirect_uri");
  });

  it("refuses a body that is not JSON", async () => {
    const res = await setup()(new Request(`${PUBLIC}/register`, { method: "POST", body: "{" }));
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_client_metadata");
  });
});

describe("authorization page", () => {
  it("shows a framing-proof, uncached form naming where the code will go", async () => {
    const h = setup();
    const res = await get(h, authQuery(authFields(await clientId(h))));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("referrer-policy")).toBe("no-referrer");
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("frame-ancestors 'none'");
    // Chrome applies form-action to the redirect after submit, which would block the return to the client.
    expect(csp).not.toContain("form-action");
    const html = await res.text();
    expect(html).toContain("claude.ai");
    expect(html).toContain('type="password"');
    expect(html).not.toContain("localhost");
  });

  it("warns when the code goes to a local process", async () => {
    const h = setup();
    const uri = "http://localhost:3118/callback";
    const html = await (await get(h, authQuery(authFields(await clientId(h, uri), { redirect_uri: uri })))).text();
    expect(html).toContain("localhost");
    expect(html).toContain("local program");
  });

  it("escapes request values it echoes into the page", async () => {
    const h = setup();
    const res = await get(h, authQuery(authFields(await clientId(h), { state: `"><script>alert(1)</script>` })));
    const html = await res.text();
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("does not redirect for an unknown client", async () => {
    const res = await get(setup(), authQuery(authFields("forged")));
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("does not accept a client id signed with another key", async () => {
    const other = await clientId(setup({ signingKey: "another-signing-key-another-signing-key-01" }));
    const res = await get(setup(), authQuery(authFields(other)));
    expect(res.status).toBe(400);
  });

  it("does not accept a token of another kind as a client id", async () => {
    const h = setup();
    const { access_token } = await tokens(h, await clientId(h));
    expect((await get(h, authQuery(authFields(access_token)))).status).toBe(400);
  });

  it("does not redirect to a URI the client did not register", async () => {
    const h = setup();
    const client = await clientId(h);
    for (const uri of [CHATGPT, "https://evil.example/cb"]) {
      const res = await get(h, authQuery(authFields(client, { redirect_uri: uri })));
      expect(res.status).toBe(400);
      expect(res.headers.get("location")).toBeNull();
    }
  });

  it("matches a registered loopback redirect on any port", async () => {
    const h = setup();
    const client = await clientId(h, "http://localhost:3118/callback");
    const res = await get(h, authQuery(authFields(client, { redirect_uri: "http://localhost:4000/callback" })));
    expect(res.status).toBe(200);
  });

  it.each([
    ["a missing challenge", { code_challenge: "" }, "invalid_request"],
    ["the plain PKCE method", { code_challenge_method: "plain" }, "invalid_request"],
    ["another response type", { response_type: "token" }, "unsupported_response_type"],
    ["a token for another resource", { resource: "https://other.example/mcp" }, "invalid_target"],
    ["no scope it can grant", { scope: "admin" }, "invalid_scope"],
  ])("sends %s back to the client as an error", async (_name, over, error) => {
    const h = setup();
    const res = await get(h, authQuery(authFields(await clientId(h), over)));
    expect(res.status).toBe(302);
    const url = new URL(res.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(CLAUDE);
    expect(url.searchParams.get("error")).toBe(error);
    expect(url.searchParams.get("state")).toBe("state-123");
    expect(url.searchParams.get("iss")).toBe(PUBLIC);
    expect(url.searchParams.get("code")).toBeNull();
  });

  it("refuses other methods", async () => {
    const res = await setup()(new Request(`${PUBLIC}/authorize`, { method: "DELETE" }));
    expect(res.status).toBe(405);
  });
});

describe("sign-in", () => {
  it("redirects with the code, the state and the issuer on the right password", async () => {
    const h = setup();
    const res = await form(h, "/authorize", { ...authFields(await clientId(h)), password: PASSWORD });
    expect(res.status).toBe(302);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const url = new URL(res.headers.get("location")!);
    expect(url.origin + url.pathname).toBe(CLAUDE);
    expect(url.searchParams.get("code")).toBeTruthy();
    expect(url.searchParams.get("state")).toBe("state-123");
    expect(url.searchParams.get("iss")).toBe(PUBLIC);
  });

  it.each([["a wrong password", "wrong"], ["an empty password", ""], ["a longer password", `${PASSWORD}x`]])(
    "shows the form again for %s and issues nothing",
    async (_name, password) => {
      const h = setup();
      const res = await form(h, "/authorize", { ...authFields(await clientId(h)), password });
      expect(res.status).toBe(401);
      expect(res.headers.get("location")).toBeNull();
      const html = await res.text();
      expect(html).toContain("Wrong password");
      expect(html).toContain('type="password"');
      expect(html).not.toContain(password || "\0");
    },
  );

  it("checks the request again on submit: the hidden fields are client-controlled", async () => {
    const h = setup();
    const res = await form(h, "/authorize", {
      ...authFields(await clientId(h), { redirect_uri: "https://evil.example/cb" }),
      password: PASSWORD,
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("location")).toBeNull();
  });

  it("does not take the password from the query string", async () => {
    const h = setup();
    const res = await get(h, authQuery({ ...authFields(await clientId(h)), password: PASSWORD }));
    expect(res.status).toBe(200);
    expect(res.headers.get("location")).toBeNull();
  });
});

describe("token endpoint", () => {
  it("exchanges a code for tokens that open the MCP endpoint", async () => {
    const h = setup();
    const client = await clientId(h);
    const res = await exchange(h, client, await issueCode(h, client));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = (await res.json()) as Tokens;
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe("garmin:read");
    expect(body.refresh_token).toBeTruthy();
    expect((await mcp(h, body.access_token)).status).toBe(200);
  });

  it("accepts a request that omits the optional resource", async () => {
    const h = setup();
    const client = await clientId(h);
    const code = await issueCode(h, client, { resource: "" });
    const res = await form(h, "/token", {
      grant_type: "authorization_code",
      code,
      client_id: client,
      redirect_uri: CLAUDE,
      code_verifier: VERIFIER,
    });
    expect(res.status).toBe(200);
  });

  it("accepts a loopback redirect whose port changed only if it is the one the code was issued for", async () => {
    const h = setup();
    const first = "http://localhost:3118/callback";
    const client = await clientId(h, first);
    const code = await issueCode(h, client, { redirect_uri: first });
    expect((await exchange(h, client, code, { redirect_uri: "http://localhost:4000/callback" })).status).toBe(400);
    expect((await exchange(h, client, code, { redirect_uri: first })).status).toBe(200);
  });

  it.each([
    ["a wrong verifier", { code_verifier: "wrong-verifier-wrong-verifier-wrong-verifier-01" }],
    ["no verifier", { code_verifier: "" }],
    ["another redirect", { redirect_uri: CHATGPT }],
    ["another resource", { resource: "https://other.example/mcp" }],
  ])("refuses %s", async (_name, over) => {
    const h = setup();
    const client = await clientId(h);
    const res = await exchange(h, client, await issueCode(h, client), over);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_grant");
  });

  it("refuses a code issued to another client", async () => {
    const h = setup();
    const code = await issueCode(h, await clientId(h));
    const other = await clientId(h, CHATGPT);
    expect(await errorOf(await exchange(h, other, code, { redirect_uri: CHATGPT }))).toBe("invalid_grant");
  });

  it("lets a code live for sixty seconds", async () => {
    const h = setup();
    const client = await clientId(h);
    const code = await issueCode(h, client);
    clock += 60;
    expect((await exchange(h, client, code)).status).toBe(200);
    clock += 1;
    const res = await exchange(h, client, code);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_grant");
  });

  it("refuses a tampered code", async () => {
    const h = setup();
    const client = await clientId(h);
    const code = await issueCode(h, client);
    expect(await errorOf(await exchange(h, client, `x${code}`))).toBe("invalid_grant");
  });

  it("refuses any other kind of token as a code", async () => {
    const h = setup();
    const client = await clientId(h);
    const { access_token, refresh_token } = await tokens(h, client);
    expect(await errorOf(await exchange(h, client, access_token))).toBe("invalid_grant");
    expect(await errorOf(await exchange(h, client, refresh_token))).toBe("invalid_grant");
  });

  it("names an unsupported grant", async () => {
    const res = await form(setup(), "/token", { grant_type: "client_credentials" });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("unsupported_grant_type");
  });

  it("refuses a client it did not issue", async () => {
    const res = await form(setup(), "/token", { grant_type: "authorization_code", code: "x", client_id: "forged" });
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid_client");
  });

  it("refuses a body that is not a form", async () => {
    const h = setup();
    const res = await h(
      new Request(`${PUBLIC}/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ grant_type: "authorization_code" }),
      }),
    );
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_request");
  });

  it("refuses GET", async () => {
    expect((await get(setup(), "/token")).status).toBe(405);
  });
});

describe("refresh", () => {
  it("returns a new access token and rotates the refresh token", async () => {
    const h = setup();
    const client = await clientId(h);
    const first = await tokens(h, client);
    const res = await refresh(h, client, first.refresh_token);
    expect(res.status).toBe(200);
    const next = (await res.json()) as Tokens;
    expect(next.refresh_token).toBeTruthy();
    expect(next.refresh_token).not.toBe(first.refresh_token);
    expect(next.access_token).not.toBe(first.access_token);
    expect((await mcp(h, next.access_token)).status).toBe(200);
  });

  it("keeps a working session alive past the first refresh token's expiry", async () => {
    const h = setup();
    const client = await clientId(h);
    const first = await tokens(h, client);
    clock += 29 * 86_400;
    const next = (await (await refresh(h, client, first.refresh_token)).json()) as Tokens;
    clock += 29 * 86_400;
    expect((await refresh(h, client, next.refresh_token)).status).toBe(200);
  });

  it("answers invalid_grant once the refresh token has expired", async () => {
    const h = setup();
    const client = await clientId(h);
    const { refresh_token } = await tokens(h, client);
    clock += 30 * 86_400 + 1;
    const res = await refresh(h, client, refresh_token);
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("invalid_grant");
  });

  it("refuses a refresh token issued to another client", async () => {
    const h = setup();
    const { refresh_token } = await tokens(h, await clientId(h));
    expect(await errorOf(await refresh(h, await clientId(h, CHATGPT), refresh_token))).toBe("invalid_grant");
  });

  it("refuses an access token as a refresh token", async () => {
    const h = setup();
    const client = await clientId(h);
    const { access_token } = await tokens(h, client);
    expect(await errorOf(await refresh(h, client, access_token))).toBe("invalid_grant");
  });

  it("refuses a refresh token for another resource", async () => {
    const h = setup();
    const client = await clientId(h);
    const { refresh_token } = await tokens(h, client);
    expect(await errorOf(await refresh(h, client, refresh_token, { resource: "https://other.example/mcp" }))).toBe("invalid_grant");
  });
});

describe("resource server", () => {
  it("still takes the static bearer token", async () => {
    expect((await mcp(setup(), STATIC)).status).toBe(200);
  });

  it("lets an access token live for an hour", async () => {
    const h = setup();
    const { access_token } = await tokens(h, await clientId(h));
    clock += 3600;
    expect((await mcp(h, access_token)).status).toBe(200);
    clock += 1;
    expect((await mcp(h, access_token)).status).toBe(401);
  });

  it("refuses a tampered token", async () => {
    const h = setup();
    const { access_token } = await tokens(h, await clientId(h));
    const [payload, signature] = access_token.split(".");
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(payload, "base64url").toString()), exp: clock + 99999 })).toString("base64url");
    expect((await mcp(h, `${forged}.${signature}`)).status).toBe(401);
  });

  it("refuses a token signed with another key", async () => {
    const other = setup({ signingKey: "another-signing-key-another-signing-key-01" });
    const { access_token } = await tokens(other, await clientId(other));
    expect((await mcp(setup(), access_token)).status).toBe(401);
  });

  it("refuses a token issued for another server, even with the same key", async () => {
    const elsewhere = "https://other.example.test";
    const other = setup({ publicUrl: elsewhere });
    const client = await clientId(other);
    const res = await form(other, "/authorize", { ...authFields(client, { resource: `${elsewhere}/mcp` }), password: PASSWORD });
    const code = new URL(res.headers.get("location")!).searchParams.get("code")!;
    const issued = await exchange(other, client, code, { resource: `${elsewhere}/mcp` });
    const { access_token } = (await issued.json()) as Tokens;
    expect((await mcp(setup(), access_token)).status).toBe(401);
  });

  it("refuses a refresh token, a code and a client id as access tokens", async () => {
    const h = setup();
    const client = await clientId(h);
    const { refresh_token } = await tokens(h, client);
    for (const token of [refresh_token, await issueCode(h, client), client]) {
      expect((await mcp(h, token)).status).toBe(401);
    }
  });
});

describe("configuration", () => {
  it.each([
    ["a short password", { password: "short" }, /OAUTH_PASSWORD/],
    ["a short signing key", { signingKey: "short" }, /OAUTH_SIGNING_KEY/],
    ["a plain http address", { publicUrl: "http://mcp.example.test" }, /MCP_PUBLIC_URL/],
    ["an address with a path", { publicUrl: "https://mcp.example.test/base" }, /MCP_PUBLIC_URL/],
    ["something that is not a URL", { publicUrl: "nope" }, /MCP_PUBLIC_URL/],
  ])("refuses to start with %s", (_name, over, message) => {
    expect(() => setup(over)).toThrow(message);
  });

  it("allows http on loopback for local testing", () => {
    expect(() => setup({ publicUrl: "http://localhost:3333" })).not.toThrow();
  });

  it("ignores a trailing slash on the public address", async () => {
    const res = await get(setup({ publicUrl: `${PUBLIC}/` }), "/.well-known/oauth-authorization-server");
    expect(((await res.json()) as { issuer: string }).issuer).toBe(PUBLIC);
  });

  const full = { MCP_PUBLIC_URL: PUBLIC, OAUTH_PASSWORD: PASSWORD, OAUTH_SIGNING_KEY: SIGNING_KEY };

  it("reads nothing when none of the variables are set", () => {
    expect(oauthConfigFromEnv({})).toBeUndefined();
  });

  it("reads all three variables", () => {
    expect(oauthConfigFromEnv(full)).toEqual({ publicUrl: PUBLIC, password: PASSWORD, signingKey: SIGNING_KEY });
  });

  it.each(Object.keys(full))("refuses a partial setup without %s rather than silently switching OAuth off", (name) => {
    const env: Record<string, string | undefined> = { ...full, [name]: undefined };
    expect(() => oauthConfigFromEnv(env)).toThrow(name);
  });
});
