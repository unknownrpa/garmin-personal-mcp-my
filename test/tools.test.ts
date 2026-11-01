import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { TokenProvider, type AuthOptions } from "../src/auth.js";
import { GarminClient } from "../src/client.js";
import { buildServer } from "../src/server.js";
import { activityZip } from "./fit-fixture.js";

type Respond = (url: URL, init?: RequestInit) => Response | Promise<Response>;

const hang = (_url: unknown, init?: RequestInit) =>
  new Promise<Response>((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
  });

async function connect(respond: Respond = () => Response.json([]), timeoutMs?: number) {
  const calls: URL[] = [];
  const inits: Array<RequestInit | undefined> = [];
  const fetchImpl = (async (url: URL, init?: RequestInit) => {
    calls.push(url);
    inits.push(init);
    return respond(url, init);
  }) as unknown as typeof fetch;
  const tokens = { host: "https://garmin.test", token: async () => "t" } as unknown as TokenProvider;
  const server = buildServer(new GarminClient(tokens, fetchImpl, timeoutMs));
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "test", version: "0" });
  await client.connect(clientSide);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const result = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text: string }> };
    return { isError: Boolean(result.isError), text: result.content[0].text };
  };
  return { call, calls, inits };
}

describe("dates", () => {
  it.each([
    ["a month that does not exist", "2024-13-01"],
    ["a day that does not exist", "2024-01-32"],
    ["the 30th of February", "2024-02-30"],
    ["a leap day in a common year", "2023-02-29"],
    ["a day of zero", "2024-01-00"],
  ])("refuses %s before calling Garmin", async (_name, date) => {
    const { call, calls } = await connect();
    expect((await call("get_steps", { startDate: date, endDate: date })).isError).toBe(true);
    expect((await call("get_sleep", { date })).isError).toBe(true);
    expect((await call("list_activities", { startDate: date })).isError).toBe(true);
    expect(calls).toEqual([]);
  });

  it("takes a real leap day", async () => {
    const { call, calls } = await connect();
    expect((await call("get_sleep", { date: "2024-02-29" })).isError).toBe(false);
    expect(calls).toHaveLength(1);
  });

  it("names the expected format", async () => {
    const { call } = await connect();
    expect((await call("get_sleep", { date: "2024-13-01" })).text).toContain("YYYY-MM-DD");
  });

  it("refuses a range that runs backwards", async () => {
    const { call, calls } = await connect();
    const { isError, text } = await call("get_steps", { startDate: "2024-01-02", endDate: "2024-01-01" });
    expect(isError).toBe(true);
    expect(text).toContain("before startDate");
    expect(calls).toEqual([]);
  });

  it("takes a one-day range", async () => {
    const { call, calls } = await connect();
    expect((await call("get_steps", { startDate: "2024-01-01", endDate: "2024-01-01" })).isError).toBe(false);
    expect(calls[0].pathname).toBe("/usersummary-service/stats/steps/daily/2024-01-01/2024-01-01");
  });
});

describe("range limits", () => {
  const ending = (days: number, end = "2026-10-31") => {
    const start = new Date(Date.parse(end) - (days - 1) * 86_400_000).toISOString().slice(0, 10);
    return { startDate: start, endDate: end };
  };

  // The longest inclusive span Garmin answered on 1 Nov 2026.
  it.each([
    ["get_steps", 28],
    ["get_stress", 28],
    ["get_hydration", 30],
    ["get_sleep_summaries", 30],
    ["get_body_battery", 30],
    ["get_daily_summaries", 366],
    ["get_hrv_summaries", 366],
    ["get_weight", 1464],
    ["get_weight_goals", 1464],
    ["get_wellness_activity_summaries", 180],
  ])("%s takes %i days and no more, counting both ends", async (name, max) => {
    const { call, calls } = await connect();
    expect((await call(name, ending(max))).isError).toBe(false);
    expect(calls).toHaveLength(1);
    const { isError, text } = await call(name, ending(max + 1));
    expect(isError).toBe(true);
    expect(text).toContain(`Range is ${max + 1} days`);
    expect(text).toContain(`up to ${max} days`);
    expect(calls).toHaveLength(1);
  });
});

describe("list_activities", () => {
  const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ activityId: i, activityName: `A${i}`, activityType: { typeKey: "running" }, privacy: {} }));

  it("offers the next page when the page is full", async () => {
    const { call, calls } = await connect(() => Response.json(rows(2)));
    const page = JSON.parse((await call("list_activities", { start: 4, limit: 2, activityType: "running" })).text);
    expect(page).toMatchObject({ start: 4, returned: 2, nextStart: 6 });
    expect(page.activities[0]).toEqual({ activityId: 0, activityName: "A0", activityType: "running" });
    expect(calls[0].searchParams.get("start")).toBe("4");
    expect(calls[0].searchParams.get("limit")).toBe("2");
    expect(calls[0].searchParams.get("activityType")).toBe("running");
  });

  it("stops at a short page", async () => {
    const { call } = await connect(() => Response.json(rows(1)));
    expect(JSON.parse((await call("list_activities", { limit: 2 })).text).nextStart).toBeNull();
  });

  it("treats an empty answer as an empty page", async () => {
    const { call } = await connect(() => new Response(""));
    expect(JSON.parse((await call("list_activities")).text)).toMatchObject({ returned: 0, nextStart: null, activities: [] });
  });

  it("refuses a page over the maximum", async () => {
    const { call, calls } = await connect();
    expect((await call("list_activities", { limit: 51 })).isError).toBe(true);
    expect(calls).toEqual([]);
  });
});

describe("Garmin errors", () => {
  it.each([400, 500])("suggests a shorter range on %i", async (status) => {
    const { call } = await connect(() => new Response("", { status }));
    const { isError, text } = await call("get_daily_summaries", { startDate: "2024-01-01", endDate: "2024-01-02" });
    expect(isError).toBe(true);
    expect(text).toContain(`${status} on /usersummary-service/v2/dailysummaries`);
    expect(text).toContain("shorter range");
  });

  it("explains a 404", async () => {
    const { call } = await connect(() => new Response("", { status: 404 }));
    expect((await call("get_raw", { path: "/nope" })).text).toContain("allowlist");
  });

  it("passes any other status through", async () => {
    const { call } = await connect(() => new Response("slow down", { status: 429 }));
    const { isError, text } = await call("get_profile");
    expect(isError).toBe(true);
    expect(text).toBe("Garmin Personal API 429 on /userprofile-service/userprofile/settings: slow down");
  });
});

describe("get_raw", () => {
  it("sends the path and the query", async () => {
    const { call, calls } = await connect(() => Response.json({ ok: true }));
    const { text } = await call("get_raw", { path: "/some-service/thing", query: { a: "1" } });
    expect(JSON.parse(text)).toEqual({ ok: true });
    expect(calls[0].href).toBe("https://garmin.test/some-service/thing?a=1");
  });

  it("returns a body that is not JSON as text", async () => {
    const { call } = await connect(() => new Response("plain"));
    expect((await call("get_raw", { path: "/x" })).text).toBe("plain");
  });

  it("refuses a path that does not start with a slash", async () => {
    const { call, calls } = await connect();
    expect((await call("get_raw", { path: "https://evil.example/" })).isError).toBe(true);
    expect(calls).toEqual([]);
  });
});

describe("get_activity_recording", () => {
  it("downloads the file and decodes it", async () => {
    const zip = activityZip(600);
    const { call, calls } = await connect(() => new Response(zip));
    const { isError, text } = await call("get_activity_recording", { activityId: 7, maxSamples: 100 });
    expect(isError).toBe(false);
    expect(calls[0].pathname).toBe("/download-service/files/activity/7");
    const summary = JSON.parse(text);
    expect(summary.fileName).toBe("7_ACTIVITY.fit");
    expect(summary.records).toMatchObject({ total: 600, returned: 100, everyNth: 6 });
  });

  it("reports a download that is not a ZIP as a tool error", async () => {
    const { call } = await connect(() => new Response("not a zip"));
    expect((await call("get_activity_recording", { activityId: 7 })).isError).toBe(true);
  });
});

describe("a Garmin that stops answering", () => {
  it("gives up and says so, instead of hanging until the platform kills the call", async () => {
    const { call } = await connect(hang, 20);
    const { isError, text } = await call("get_profile");
    expect(isError).toBe(true);
    expect(text).toContain("Garmin did not answer");
  });

  it("sends a deadline with every request by default", async () => {
    const { call, inits } = await connect();
    await call("get_profile");
    expect(inits[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("gives up on the key exchange too", async () => {
    const options: AuthOptions = { apiKey: "k", cacheFile: "/nonexistent/dir/t.json", fetchImpl: hang as unknown as typeof fetch, timeoutMs: 20 };
    await expect(new TokenProvider(options).token()).rejects.toMatchObject({ name: "TimeoutError" });
  });
});

describe("response size", () => {
  const OVER = 4_000_000;

  it("refuses an answer too big to return, naming its size", async () => {
    const { call } = await connect(() => Response.json("x".repeat(OVER + 1000)));
    const { isError, text } = await call("get_raw", { path: "/big" });
    expect(isError).toBe(true);
    expect(text.length).toBeLessThan(300);
    expect(text).toMatch(/4\.0 ?MB/);
  });

  it("measures what goes on the wire: quotes are escaped twice", async () => {
    const quotes = '"'.repeat(1_100_000);
    const { call } = await connect(() => Response.json({ quotes }));
    const { isError } = await call("get_raw", { path: "/big" });
    expect(isError).toBe(true);
  });

  it("applies to the named tools as well", async () => {
    const { call } = await connect(() => Response.json("x".repeat(OVER + 1000)));
    expect((await call("get_daily_summaries", { startDate: "2024-01-01", endDate: "2024-01-02" })).isError).toBe(true);
  });

  it("lets a large answer under the limit through", async () => {
    const body = "x".repeat(3_000_000);
    const { call } = await connect(() => Response.json(body));
    const { isError, text } = await call("get_raw", { path: "/big" });
    expect(isError).toBe(false);
    expect(text).toHaveLength(body.length);
  });
});
