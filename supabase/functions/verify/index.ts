// Verity verify API: checks an NTAG 424 DNA tap and records it.
// GET /functions/v1/verify?b=<brandSlug>&p=<32 hex>&m=<16 hex>[&tz=<IANA zone>][&qc=1]
// Public (no JWT needed). With qc=1 and a staff JWT, the answer includes technical detail and the
// scan is logged as a staff check rather than a shopper scan.
import { createClient } from "jsr:@supabase/supabase-js@2";
import { hexToBytes, tagKeys, verifySun, type BrandKeys } from "../_shared/ntag.ts";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

// Small per-instance rate limit: 30 checks per minute per IP.
const hits = new Map<string, number[]>();
function limited(ip: string): boolean {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < 60_000);
  recent.push(now);
  hits.set(ip, recent);
  return recent.length > 30;
}

function placeFromZone(tz: string | null): string | null {
  if (!tz || !/^[A-Za-z_]+\/[A-Za-z_\/-]+$/.test(tz)) return null;
  const city = tz.split("/").pop()!.replace(/_/g, " ");
  return city.length <= 40 ? city : null;
}

async function isStaff(authHeader: string | null): Promise<boolean> {
  if (!authHeader?.startsWith("Bearer ")) return false;
  const { data } = await db.auth.getUser(authHeader.slice(7));
  if (!data?.user) return false;
  const { data: row } = await db.from("staff").select("user_id").eq("user_id", data.user.id).maybeSingle();
  return !!row;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  const url = new URL(req.url);
  const q = req.method === "POST" ? new URLSearchParams(await req.json().then((b) => b ?? {}).catch(() => ({}))) : url.searchParams;
  const slug = (q.get("b") ?? "").toLowerCase();
  const p = q.get("p") ?? "", m = q.get("m") ?? "";
  const place = placeFromZone(q.get("tz"));
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "unknown";
  if (limited(ip)) return json({ verdict: "RATE_LIMITED" }, 429);

  const qc = q.get("qc") === "1" && (await isStaff(req.headers.get("Authorization")));
  const source = qc ? "qc" : "shopper";

  // MIFARE Ultralight TEST tags carry only ?s=<short code> (they hold 48 bytes). No counter, no
  // signature: every tap shows the product, so these prove the flow, not authenticity.
  const sc = (q.get("s") ?? "").toUpperCase();
  if (sc && !slug) {
    if (!/^[0-9A-Z]{4,12}$/.test(sc)) return json({ verdict: "BROKEN_LINK", reason: "The link is incomplete." });
    const { data: st } = await db.from("tags")
      .select("id, uid, status, scan_count, first_scan_at, brand_id, brands(name, accent, story, link_label, link_url), batches(product_id, products(name, details))")
      .eq("short_code", sc).maybeSingle();
    if (!st) return json({ verdict: "UNKNOWN_TAG", reason: "No test tag has this code." });
    // deno-lint-ignore no-explicit-any
    const sb: any = (st as any).brands ?? {}, sbat: any = (st as any).batches ?? null;
    const sOut = { name: sb.name, accent: sb.accent, story: sb.story, linkLabel: sb.link_label, linkUrl: sb.link_url };
    const sProduct = sbat?.products ?? null;
    const ok = st.status === "active";
    const verdict = ok ? "GENUINE" : "CANCELLED_TAG";
    await db.from("scans").insert({ brand_id: st.brand_id, verdict, source, place, uid: st.uid, tag_id: st.id,
      product_id: sbat?.product_id ?? null, user_agent: (req.headers.get("user-agent") ?? "").slice(0, 200) });
    if (ok && !qc) {
      const now = new Date().toISOString();
      await db.from("tags").update({ scan_count: st.scan_count + 1, last_scan_at: now, first_scan_at: st.first_scan_at ?? now }).eq("id", st.id);
    }
    return json({ verdict, brand: sOut, product: sProduct, scanCount: st.scan_count + (ok && !qc ? 1 : 0), testTag: true, staticTag: true,
      ...(qc ? { tech: { uid: st.uid, chip: "ultralight", reason: ok ? "STATIC TEST TAG: no counter or signature, copies can't be detected." : `Tag status is ${st.status}.` } } : {}) });
  }

  const { data: brand } = await db.from("brands")
    .select("id, slug, name, accent, story, link_label, link_url").eq("slug", slug).maybeSingle();
  if (!brand) return json({ verdict: "BROKEN_LINK", reason: "Unknown brand in link" });
  const brandOut = { name: brand.name, accent: brand.accent, story: brand.story, linkLabel: brand.link_label, linkUrl: brand.link_url };

  const { data: keys, error: keyErr } = await db.rpc("get_brand_keys", { p_brand_id: brand.id });
  if (keyErr || !keys) return json({ verdict: "ERROR", reason: "Brand keys unavailable" }, 500);
  const bk = keys as BrandKeys;

  const sun = await verifySun(bk.meta, p, m, async (uid) => hexToBytes((await tagKeys(bk, uid)).k2));

  const record = async (verdict: string, extra: Record<string, unknown> = {}) => {
    const { data } = await db.from("scans").insert({
      brand_id: brand.id, verdict, source, place,
      user_agent: (req.headers.get("user-agent") ?? "").slice(0, 200), ...extra,
    }).select("id").single();
    return data?.id as number | undefined;
  };
  const alert = async (rule: string, severity: string, message: string, scanId?: number, tagId?: string) => {
    if (qc) return;
    await db.from("alerts").insert({ brand_id: brand.id, tag_id: tagId ?? null, scan_id: scanId ?? null, rule, severity, message });
  };

  async function testTag21x(mirror: string) {
    const mm = /^([0-9A-Fa-f]{14})x([0-9A-Fa-f]{6})$/.exec(mirror);
    if (!mm) {
      await record("BROKEN_LINK");
      return json({ verdict: "BROKEN_LINK", brand: brandOut, reason: "The link is incomplete." });
    }
    const tuid = mm[1].toUpperCase(), tctr = parseInt(mm[2], 16);
    const { data: t } = await db.from("tags")
      .select("id, status, chip, last_ctr, scan_count, batches(product_id, products(name, details))")
      .eq("brand_id", brand.id).eq("uid", tuid).maybeSingle();
    // deno-lint-ignore no-explicit-any
    const tb = (t as any)?.batches ?? null;
    const tp = tb?.products ?? null, tpid = tb?.product_id ?? null;
    const ttech = (extra: Record<string, unknown>) => (qc ? { tech: { uid: tuid, ctr: tctr, lastCtr: t?.last_ctr ?? null, chip: t?.chip ?? null, ...extra } } : {});
    if (!t || t.chip !== "ntag21x") {
      const id = await record(t ? "FORGED" : "UNKNOWN_TAG", { uid: tuid, ctr: tctr, tag_id: t?.id ?? null });
      await alert(t ? "forgery" : "unknown", t ? "high" : "medium",
        t ? `Tag ${tuid} is a secure tag but sent an unsigned test link.` : `Test tag ${tuid} was never registered.`, id, t?.id);
      return json({ verdict: t ? "FORGED" : "UNKNOWN_TAG", brand: brandOut, ...ttech({ reason: t ? "Secure tags never send unsigned links." : "Not registered." }) });
    }
    if (t.status !== "active") {
      const id = await record("CANCELLED_TAG", { uid: tuid, ctr: tctr, tag_id: t.id, product_id: tpid });
      await alert("cancelled", "medium", `Cancelled test tag ${tuid} was scanned.`, id, t.id);
      return json({ verdict: "CANCELLED_TAG", brand: brandOut, product: tp, testTag: true, ...ttech({ reason: `Tag status is ${t.status}.` }) });
    }
    const { data: ok } = await db.rpc("accept_counter", { p_tag_id: t.id, p_ctr: tctr, p_count: !qc });
    if (!ok) {
      const id = await record("REPLAYED", { uid: tuid, ctr: tctr, tag_id: t.id, product_id: tpid });
      await alert("replay", "high", `An old link for test tag ${tuid} was opened again (counter ${tctr}, last accepted ${t.last_ctr}).`, id, t.id);
      return json({ verdict: "REPLAYED", brand: brandOut, product: tp, testTag: true, ...ttech({ reason: `Counter ${tctr} is not higher than the last accepted ${t.last_ctr}.` }) });
    }
    await record("GENUINE", { uid: tuid, ctr: tctr, tag_id: t.id, product_id: tpid });
    return json({ verdict: "GENUINE", brand: brandOut, product: tp, scanCount: t.scan_count + (qc ? 0 : 1), testTag: true,
      ...ttech({ reason: "TEST TAG: counter moved forward. No signature, so this is not proof of authenticity." }) });
  }

  // NTAG213/215/216 TEST tags: the tag mirrors "<UID>x<counter>" into u=. No signature, so this only
  // proves the counter went up. Only tags registered as chip 'ntag21x' may use this path.
  const u = q.get("u") ?? "";
  if (u && !p) return await testTag21x(u);

  if (!sun.ok && sun.reason === "format") {
    await record("BROKEN_LINK");
    return json({ verdict: "BROKEN_LINK", brand: brandOut, reason: "The link is incomplete." });
  }
  if (!sun.ok && sun.reason === "picc") {
    const id = await record("FORGED");
    await alert("forgery", "high", "A tap could not be decrypted with this brand's key. Possible fake tag.", id);
    return json({ verdict: "FORGED", brand: brandOut, ...(qc ? { tech: { reason: "PICCData did not decrypt to a valid header (0xC7)." } } : {}) });
  }

  const uid = sun.uid!;
  const { data: tag } = await db.from("tags")
    .select("id, status, chip, last_ctr, scan_count, batches(product_id, products(name, details))")
    .eq("brand_id", brand.id).eq("uid", uid).maybeSingle();

  // deno-lint-ignore no-explicit-any
  const batch = (tag as any)?.batches ?? null;
  const product = batch?.products ?? null;
  const productId = batch?.product_id ?? null;
  const tech = (extra: Record<string, unknown>) => ({ ...(tag?.chip === "virtual" ? { testTag: true } : {}), ...(qc ? { tech: { uid, ctr: sun.ctr, lastCtr: tag?.last_ctr ?? null, ...extra } } : {}) });

  if (!tag) {
    const id = await record("UNKNOWN_TAG", { uid, ctr: sun.ctr });
    await alert("unknown", "medium", `Tag ${uid} was never registered for this brand.`, id);
    return json({ verdict: "UNKNOWN_TAG", brand: brandOut, ...tech({ reason: "No tag with this UID is registered." }) });
  }
  if (!sun.ok) {
    const id = await record("FORGED", { uid, ctr: sun.ctr, tag_id: tag.id, product_id: productId });
    await alert("forgery", "high", `Signature check failed for tag ${uid}.`, id, tag.id);
    return json({ verdict: "FORGED", brand: brandOut, ...tech({ reason: "Signature does not match this tag's key.", gotMac: sun.gotMac, expectedMac: sun.expectedMac }) });
  }
  if (tag.status !== "active") {
    const id = await record("CANCELLED_TAG", { uid, ctr: sun.ctr, tag_id: tag.id, product_id: productId });
    await alert("cancelled", "medium", `Cancelled tag ${uid} was scanned.`, id, tag.id);
    return json({ verdict: "CANCELLED_TAG", brand: brandOut, product, ...tech({ reason: `Tag status is ${tag.status}.` }) });
  }

  const { data: accepted } = await db.rpc("accept_counter", { p_tag_id: tag.id, p_ctr: sun.ctr, p_count: !qc });
  if (!accepted) {
    const id = await record("REPLAYED", { uid, ctr: sun.ctr, tag_id: tag.id, product_id: productId });
    await alert("replay", "high", `An old link for tag ${uid} was opened again (counter ${sun.ctr}, last accepted ${tag.last_ctr}).`, id, tag.id);
    return json({ verdict: "REPLAYED", brand: brandOut, product, ...tech({ reason: `Counter ${sun.ctr} is not higher than the last accepted ${tag.last_ctr}.` }) });
  }

  const scanId = await record("GENUINE", { uid, ctr: sun.ctr, tag_id: tag.id, product_id: productId });
  const scanCount = tag.scan_count + (qc ? 0 : 1);

  // Two places within an hour (shopper scans only).
  if (!qc && place) {
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { data: prev } = await db.from("scans").select("place")
      .eq("tag_id", tag.id).eq("verdict", "GENUINE").eq("source", "shopper").gte("created_at", since)
      .neq("id", scanId ?? -1).not("place", "is", null).limit(5);
    const other = prev?.find((s) => s.place !== place);
    if (other) await alert("two_places", "medium", `Tag ${uid} scanned in ${other.place} and ${place} within an hour.`, scanId, tag.id);
  }

  return json({ verdict: "GENUINE", brand: brandOut, product, scanCount, ...tech({ reason: "Signature valid and counter moved forward." }) });
});
