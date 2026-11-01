/** A synthetic activity, built with Garmin's own encoder so no real recording ever enters the repo. */
import { Encoder, Profile } from "@garmin/fitsdk";
import { zipSync } from "fflate";

export const START = new Date("2024-01-01T10:00:00.000Z");

const at = (seconds: number) => new Date(START.getTime() + seconds * 1000);

export function activityFit(records: number, laps = 2): Uint8Array {
  const encoder = new Encoder();
  encoder.onMesg(Profile.MesgNum.FILE_ID, { type: "activity", manufacturer: "garmin", product: 1, timeCreated: START, serialNumber: 1 });
  for (let i = 0; i < records; i++) {
    encoder.onMesg(Profile.MesgNum.RECORD, { timestamp: at(i), heartRate: 100 + (i % 80), power: 200, distance: i * 3 });
  }
  for (let i = 0; i < laps; i++) {
    encoder.onMesg(Profile.MesgNum.LAP, { timestamp: at(records), messageIndex: i, totalElapsedTime: records / laps });
  }
  encoder.onMesg(Profile.MesgNum.SESSION, { timestamp: at(records), messageIndex: 0, sport: "running", totalElapsedTime: records, numLaps: laps });
  return encoder.close();
}

export function activityZip(records: number): Uint8Array {
  return zipSync({ "7_ACTIVITY.fit": activityFit(records) });
}
