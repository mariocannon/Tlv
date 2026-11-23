// Run: node --experimental-strip-types supabase/tests/ntag.test.ts
import { bytesToHex, cmac, diversify, hexToBytes, simulateTap, sunMac, verifySun } from "../functions/_shared/ntag.ts";

let failed = 0;
function eq(name: string, got: string, want: string) {
  const ok = got.toUpperCase() === want.toUpperCase();
  if (!ok) failed++;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : `\n  got  ${got}\n  want ${want}`}`);
}

const Z = "00000000000000000000000000000000";

// RFC 4493 AES-CMAC vectors
const rk = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
eq("CMAC empty", bytesToHex(await cmac(rk, new Uint8Array(0))), "bb1d6929e95937287fa37d129b756746");
eq("CMAC 16", bytesToHex(await cmac(rk, hexToBytes("6bc1bee22e409f96e93d7e117393172a"))), "070a16b46b4d4144f79bdd9dd04a287c");
eq("CMAC 40", bytesToHex(await cmac(rk, hexToBytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"))), "dfa66747de9ae63030ca32611497c827");

// AN12196 SUN example: all-zero keys, PICCData EF96..., MAC 94EE...
const r = await verifySun(Z, "EF963FF7828658A599F3041510671E88", "94EED9EE65337086", async () => hexToBytes(Z));
eq("SUN verdict", String(r.ok), "true");
if (r.ok) { eq("SUN uid", r.uid, "04DE5F1EACC040"); eq("SUN ctr", String(r.ctr), "61"); }
eq("SUN mac", bytesToHex(await sunMac(hexToBytes(Z), hexToBytes("04DE5F1EACC040"), hexToBytes("3D0000"))), "94EED9EE65337086");

// Tampered MAC must fail
const bad = await verifySun(Z, "EF963FF7828658A599F3041510671E88", "94EED9EE65337087", async () => hexToBytes(Z));
eq("SUN tampered", String(bad.ok), "false");

// AN10922 diversification: must match the Java KeyDiversifier (cross-checked in CoreTests).
eq("AN10922", bytesToHex(await diversify(hexToBytes("00112233445566778899AABBCCDDEEFF"),
  hexToBytes("04782E21801D803042F54E585020416275"))), "A8DD63A3B89D54B37CA802473FDA9175");

// Round trip with random keys
const meta = "A1A2A3A4A5A6A7A8A9AAABACADAEAFB0", fk = hexToBytes("0F0E0D0C0B0A09080706050403020100");
const sim = await simulateTap(meta, fk, "04A35B128C6E80", 128);
const rt = await verifySun(meta, sim.p, sim.m, async () => fk);
eq("round trip", JSON.stringify(rt.ok ? [rt.uid, rt.ctr] : rt), JSON.stringify(["04A35B128C6E80", 128]));

console.log(failed ? `${failed} FAILED` : "All TypeScript crypto tests passed");
if (failed) process.exit(1);
