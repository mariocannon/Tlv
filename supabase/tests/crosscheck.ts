// Checks that a tap URL produced by the Java encoder + simulated tag verifies with the server's TypeScript code,
// and that both sides derive the same per-tag keys.
import { readFileSync } from "node:fs";
import { hexToBytes, tagKeys, verifySun } from "../functions/_shared/ntag.ts";

const x = JSON.parse(readFileSync(process.argv[2], "utf8"));
const keys = await tagKeys({ meta: x.meta, mac: x.mac, cfg: x.cfg }, x.uid);
const q = new URL(x.url).searchParams;
const r = await verifySun(keys.k1, q.get("p")!, q.get("m")!, async () => hexToBytes(keys.k2));
const ok = keys.k0 === x.k0 && r.ok && r.uid === x.uid;
console.log(`${ok ? "PASS" : "FAIL"} Java-encoded tap verifies with the server code (uid ${r.ok ? r.uid : "-"}, ctr ${r.ok ? r.ctr : "-"}), same per-tag keys`);
if (!ok) process.exit(1);
