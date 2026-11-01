import { describe, expect, it } from "vitest";
import { zipSync } from "fflate";
import { extractFit, summarizeFit } from "../src/fit.js";
import { START, activityFit } from "./fit-fixture.js";

describe("extractFit", () => {
  const bytes = new Uint8Array([1, 2, 3]);

  it("finds the FIT file among other entries, whatever its case", () => {
    const { fileName, bytes: found } = extractFit(zipSync({ "readme.txt": new Uint8Array([9]), "7_ACTIVITY.FIT": bytes }));
    expect(fileName).toBe("7_ACTIVITY.FIT");
    expect([...found]).toEqual([1, 2, 3]);
  });

  it("falls back to the first entry when nothing is named .fit", () => {
    expect(extractFit(zipSync({ "activity.bin": bytes })).fileName).toBe("activity.bin");
  });

  it("refuses an empty archive", () => {
    expect(() => extractFit(zipSync({}))).toThrow("no files");
  });
});

describe("summarizeFit", () => {
  it("returns the session and every lap, with dates as strings and bookkeeping dropped", () => {
    const summary = summarizeFit(activityFit(10, 3), "a.fit");
    expect(summary.fileName).toBe("a.fit");
    expect(summary.session).toMatchObject({ sport: "running", totalElapsedTime: 10 });
    expect(summary.session).not.toHaveProperty("timestamp");
    expect(summary.session).not.toHaveProperty("messageIndex");
    expect(summary.laps).toHaveLength(3);
    expect(summary.messageCounts).toMatchObject({ record: 10, lap: 3, session: 1 });
    expect(summary.decodeErrors).toBe(0);
  });

  it("returns every record when they fit", () => {
    const { records } = summarizeFit(activityFit(10), "a.fit", 300);
    expect(records).toMatchObject({ total: 10, returned: 10, everyNth: 1 });
  });

  it("downsamples evenly and never returns more than asked", () => {
    const { records } = summarizeFit(activityFit(1000), "a.fit", 300);
    expect(records.total).toBe(1000);
    expect(records.everyNth).toBe(4);
    expect(records.returned).toBe(250);
    expect(records.returned).toBeLessThanOrEqual(300);
    expect(records.samples[1].elapsedTime).toBe(4);
  });

  it("gives each sample a timestamp and seconds since the start", () => {
    const { records } = summarizeFit(activityFit(10), "a.fit");
    expect(records.samples[0]).toMatchObject({ timestamp: START.toISOString(), elapsedTime: 0, heartRate: 100, power: 200 });
    expect(records.samples[3]).toMatchObject({ elapsedTime: 3, heartRate: 103 });
    expect(records.fields).toEqual(expect.arrayContaining(["timestamp", "elapsedTime", "heartRate", "power", "distance"]));
  });

  it("copes with an activity that recorded nothing", () => {
    const { records, session } = summarizeFit(activityFit(0, 0), "a.fit");
    expect(records).toMatchObject({ total: 0, returned: 0, samples: [] });
    expect(session).not.toBeNull();
  });
});
