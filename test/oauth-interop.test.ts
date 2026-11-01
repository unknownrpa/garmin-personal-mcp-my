/** The whole sign-in, driven by the MCP SDK's own OAuth client and its strict schemas. */
import { describe, expect, it } from "vitest";
import {
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
  exchangeAuthorization,
  extractWWWAuthenticateParams,
  refreshAuthorization,
  registerClient,
  startAuthorization,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { createFetchHandler } from "../src/http.js";

const PUBLIC = "https://mcp.example.test";
const RESOURCE = new URL(`${PUBLIC}/mcp`);
const CALLBACK = "https://claude.ai/api/mcp/auth_callback";
const PASSWORD = "correct-horse-battery-staple-0123456789";

const handler = createFetchHandler({
  apiKey: "k",
  bearerToken: "static-bearer-token",
  oauth: { publicUrl: PUBLIC, password: PASSWORD, signingKey: "signing-key-signing-key-signing-key-0123" },
});

const fetchFn = ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch;

const listTools = (token?: string) =>
  handler(
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

describe("the MCP SDK's OAuth client", () => {
  it("discovers, registers, signs in, calls and refreshes", async () => {
    const challenge = extractWWWAuthenticateParams(await listTools());
    expect(challenge.resourceMetadataUrl?.href).toBe(`${PUBLIC}/.well-known/oauth-protected-resource`);
    expect(challenge.scope).toBe("garmin:read");

    const resourceMetadata = await discoverOAuthProtectedResourceMetadata(RESOURCE, { resourceMetadataUrl: challenge.resourceMetadataUrl }, fetchFn);
    expect(resourceMetadata.resource).toBe(RESOURCE.href);
    const issuer = resourceMetadata.authorization_servers![0];

    const metadata = await discoverAuthorizationServerMetadata(issuer, { fetchFn });
    expect(metadata?.issuer).toBe(PUBLIC);

    const clientInformation = await registerClient(issuer, {
      metadata,
      clientMetadata: { client_name: "Interop", redirect_uris: [CALLBACK], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] },
      fetchFn,
    });

    const { authorizationUrl, codeVerifier } = await startAuthorization(issuer, {
      metadata,
      clientInformation,
      redirectUrl: CALLBACK,
      scope: challenge.scope,
      state: "interop-state",
      resource: RESOURCE,
    });

    const opened = await handler(new Request(authorizationUrl));
    expect(opened.status).toBe(200);

    const submit = new URLSearchParams(authorizationUrl.searchParams);
    submit.set("password", PASSWORD);
    const signedIn = await handler(
      new Request(`${PUBLIC}/authorize`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: submit.toString() }),
    );
    expect(signedIn.status).toBe(302);
    const callback = new URL(signedIn.headers.get("location")!);
    expect(callback.searchParams.get("state")).toBe("interop-state");
    expect(callback.searchParams.get("iss")).toBe(metadata?.issuer);

    const tokens = await exchangeAuthorization(issuer, {
      metadata,
      clientInformation,
      authorizationCode: callback.searchParams.get("code")!,
      codeVerifier,
      redirectUri: CALLBACK,
      resource: RESOURCE,
      fetchFn,
    });
    expect((await listTools(tokens.access_token)).status).toBe(200);

    const refreshed = await refreshAuthorization(issuer, {
      metadata,
      clientInformation,
      refreshToken: tokens.refresh_token!,
      resource: RESOURCE,
      fetchFn,
    });
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    expect((await listTools(refreshed.access_token)).status).toBe(200);
  });
});
