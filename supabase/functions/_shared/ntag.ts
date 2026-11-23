// NTAG 424 DNA crypto for Verity: AES-CMAC (RFC 4493), AN10922 key diversification,
// and SUN/SDM verification (AN12196). Uses only WebCrypto, so it runs in Deno and Node 20+.

export type BrandKeys = { meta: string; mac: string; cfg: string };
export type TagKeys = { k0: string; k1: string; k2: string; k3: string; k4: string };

const subtle = globalThis.crypto.subtle;

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error("bad hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function xor16(a: Uint8Array, b: Uint8Array): Uint8Array {
  const o = new Uint8Array(16);
  for (let i = 0; i < 16; i++) o[i] = a[i] ^ b[i];
  return o;
}

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  return await subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

/** AES-128 encrypt of one block (ECB), built from WebCrypto CBC with a zero IV. */
async function encryptBlock(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, block));
  return ct.slice(0, 16);
}

/** AES-128-CBC decrypt of one block with a zero IV. WebCrypto insists on PKCS#7 padding, so we
 *  append a crafted block that decrypts to a full padding block. */
async function decryptBlockZeroIv(key: CryptoKey, c: Uint8Array): Promise<Uint8Array> {
  const pad = new Uint8Array(16).fill(16);
  const extra = await encryptBlock(key, xor16(c, pad));
  const pt = new Uint8Array(
    await subtle.decrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, concat(c, extra)),
  );
  return pt.slice(0, 16);
}

function shiftLeft(b: Uint8Array): Uint8Array {
  const o = new Uint8Array(16);
  let carry = 0;
  for (let i = 15; i >= 0; i--) {
    o[i] = ((b[i] << 1) | carry) & 0xff;
    carry = b[i] >> 7;
  }
  if (b[0] & 0x80) o[15] ^= 0x87;
  return o;
}

async function subkeys(key: CryptoKey): Promise<[Uint8Array, Uint8Array]> {
  const l = await encryptBlock(key, new Uint8Array(16));
  const k1 = shiftLeft(l);
  return [k1, shiftLeft(k1)];
}

/** AES-CMAC (RFC 4493). */
export async function cmac(keyBytes: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const key = await importKey(keyBytes);
  const [k1, k2] = await subkeys(key);
  const n = Math.max(1, Math.ceil(msg.length / 16));
  const s = (n - 1) * 16;
  let last: Uint8Array;
  if (msg.length > 0 && msg.length % 16 === 0) {
    last = xor16(msg.slice(s, s + 16), k1);
  } else {
    const p = new Uint8Array(16);
    p.set(msg.slice(s));
    p[msg.length - s] = 0x80;
    last = xor16(p, k2);
  }
  let x = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) x = await encryptBlock(key, xor16(x, msg.slice(i * 16, i * 16 + 16)));
  return await encryptBlock(key, xor16(x, last));
}

/** NXP AN10922 AES-128 diversification: CMAC over 0x01 || input, padded to 32 bytes. */
export async function diversify(master: Uint8Array, input: Uint8Array): Promise<Uint8Array> {
  if (input.length < 1 || input.length > 31) throw new Error("diversification input must be 1..31 bytes");
  const key = await importKey(master);
  const [k1, k2] = await subkeys(key);
  const m = concat(new Uint8Array([0x01]), input);
  const block = new Uint8Array(32);
  block.set(m);
  if (m.length === 32) {
    block.set(xor16(block.slice(16), k1), 16);
  } else {
    block[m.length] = 0x80;
    block.set(xor16(block.slice(16), k2), 16);
  }
  const b1 = await encryptBlock(key, block.slice(0, 16));
  return await encryptBlock(key, xor16(b1, block.slice(16)));
}

const LABEL = new TextEncoder().encode("VRTY");

/** Per-tag key input: UID(7) || "VRTY" || keyNo. */
function divInput(uid: Uint8Array, keyNo: number): Uint8Array {
  return concat(uid, LABEL, new Uint8Array([keyNo]));
}

/**
 * The five AES keys written to a tag.
 *  k0 app master (per tag), k1 SDM meta-read (shared per brand, so the server can decrypt before it
 *  knows the UID), k2 SDM file-read / MAC key (per tag), k3, k4 unused but locked (per tag).
 */
export async function tagKeys(brand: BrandKeys, uidHex: string): Promise<TagKeys> {
  const uid = hexToBytes(uidHex);
  if (uid.length !== 7) throw new Error("UID must be 7 bytes");
  const cfg = hexToBytes(brand.cfg), mac = hexToBytes(brand.mac);
  return {
    k0: bytesToHex(await diversify(cfg, divInput(uid, 0))),
    k1: bytesToHex(hexToBytes(brand.meta)),
    k2: bytesToHex(await diversify(mac, divInput(uid, 2))),
    k3: bytesToHex(await diversify(cfg, divInput(uid, 3))),
    k4: bytesToHex(await diversify(cfg, divInput(uid, 4))),
  };
}

/** Constant-time comparison of two equal-length byte arrays. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export type SunResult =
  | { ok: true; uid: string; ctr: number; mac: string }
  | { ok: false; reason: "format" | "picc" | "mac"; uid?: string; ctr?: number; gotMac?: string; expectedMac?: string };

/** Truncated SDM MAC over an empty input (MAC input offset == MAC offset), per AN12196. */
export async function sunMac(fileReadKey: Uint8Array, uid: Uint8Array, ctrLe: Uint8Array): Promise<Uint8Array> {
  const sv2 = concat(new Uint8Array([0x3c, 0xc3, 0x00, 0x01, 0x00, 0x80]), uid, ctrLe);
  const ses = await cmac(fileReadKey, sv2);
  const full = await cmac(ses, new Uint8Array(0));
  return new Uint8Array([1, 3, 5, 7, 9, 11, 13, 15].map((i) => full[i]));
}

/**
 * Check a tap. p = 16-byte encrypted PICCData (hex), m = 8-byte SDM MAC (hex).
 * getFileKey derives the per-tag file-read key from the decrypted UID.
 */
export async function verifySun(
  metaKeyHex: string,
  pHex: string,
  mHex: string,
  getFileKey: (uidHex: string) => Promise<Uint8Array>,
): Promise<SunResult> {
  if (!/^[0-9a-fA-F]{32}$/.test(pHex) || !/^[0-9a-fA-F]{16}$/.test(mHex)) return { ok: false, reason: "format" };
  const metaKey = await importKey(hexToBytes(metaKeyHex));
  const plain = await decryptBlockZeroIv(metaKey, hexToBytes(pHex));
  if (plain[0] !== 0xc7) return { ok: false, reason: "picc" };
  const uid = plain.slice(1, 8);
  const ctrLe = plain.slice(8, 11);
  const ctr = ctrLe[0] | (ctrLe[1] << 8) | (ctrLe[2] << 16);
  const uidHex = bytesToHex(uid);
  const expected = await sunMac(await getFileKey(uidHex), uid, ctrLe);
  const got = hexToBytes(mHex);
  if (!sameBytes(expected, got)) {
    return { ok: false, reason: "mac", uid: uidHex, ctr, gotMac: bytesToHex(got), expectedMac: bytesToHex(expected) };
  }
  return { ok: true, uid: uidHex, ctr, mac: bytesToHex(got) };
}

/** Build the PICCData + MAC a real tag would produce. Used by tests and the demo simulator. */
export async function simulateTap(metaKeyHex: string, fileKey: Uint8Array, uidHex: string, ctr: number) {
  const uid = hexToBytes(uidHex);
  const ctrLe = new Uint8Array([ctr & 0xff, (ctr >> 8) & 0xff, (ctr >> 16) & 0xff]);
  const plain = concat(new Uint8Array([0xc7]), uid, ctrLe, globalThis.crypto.getRandomValues(new Uint8Array(5)));
  const key = await importKey(hexToBytes(metaKeyHex));
  const p = await encryptBlock(key, plain);
  const m = await sunMac(fileKey, uid, ctrLe);
  return { p: bytesToHex(p), m: bytesToHex(m) };
}
