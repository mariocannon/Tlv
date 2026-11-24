// Verity encoder API, called by the CardForge app (staff only, JWT required).
// POST /functions/v1/encoder  { action, ... }
//   list_batches                      -> batches with brand + product
//   tag_keys   { batch_id, uid }      -> the five AES keys for this tag + the URL template to write
//   register   { batch_id, uid }      -> records the tag as encoded and active
//   reset_keys { uid }                -> current keys of an encoded tag, so the app can wipe it back to factory
//   mark_reset { uid }                -> marks a wiped tag as reset
//   register_21x { batch_id, uid }    -> registers an NTAG213/215/216 TEST tag (no crypto) and returns its URL template
//   register_static { batch_id, uid } -> registers a MIFARE Ultralight TEST tag with a short static link ?s=<code>
//   test_create { batch_id }          -> makes a virtual test tag (no hardware) in a batch
//   test_tap   { tag_id }             -> the virtual tag "taps": returns a fresh signed tap URL
//   test_old_link { tag_id }          -> the previous URL of a virtual tag (to demo a copied link)
// MVP note: keys travel to the phone over TLS for one tag at a time. Production should wrap them
// to a per-session device key (see the spec, section 5.3).
import { createClient } from "jsr:@supabase/supabase-js@2";
import { bytesToHex, hexToBytes, simulateTap, tagKeys, type BrandKeys } from "../_shared/ntag.ts";

const TAP_BASE = Deno.env.get("VERITY_TAP_BASE") ?? "https://mariocannon.github.io/Tlv/t/";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json", "Cache-Control": "no-store" } });

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

function urlTemplate(slug: string): string {
  return `${TAP_BASE}?b=${slug}&p=${"0".repeat(32)}&m=${"0".repeat(16)}`;
}

async function brandKeys(brandId: string): Promise<BrandKeys> {
  const { data, error } = await db.rpc("get_brand_keys", { p_brand_id: brandId });
  if (error || !data) throw new Error("Brand keys unavailable");
  return data as BrandKeys;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);

  const auth = req.headers.get("Authorization") ?? "";
  const { data: who } = await db.auth.getUser(auth.replace(/^Bearer /, ""));
  if (!who?.user) return json({ error: "Sign in again" }, 401);
  const { data: staff } = await db.from("staff").select("user_id").eq("user_id", who.user.id).maybeSingle();
  if (!staff) return json({ error: "This account is not Verity staff" }, 403);

  // deno-lint-ignore no-explicit-any
  const body: any = await req.json().catch(() => ({}));
  const uid = typeof body.uid === "string" ? body.uid.toUpperCase() : "";
  if (body.uid !== undefined && !/^[0-9A-F]{14}$/.test(uid)) return json({ error: "UID must be 7 bytes (14 hex)" }, 400);

  try {
    switch (body.action) {
      case "list_batches": {
        const { data, error } = await db.from("batches")
          .select("id, code, planned_qty, tag_type, brands(slug, name), products(name), tags(count)")
          .order("created_at", { ascending: false });
        if (error) throw error;
        // deno-lint-ignore no-explicit-any
        return json({ batches: (data ?? []).map((b: any) => ({
          id: b.id, code: b.code, planned: b.planned_qty, tagType: b.tag_type,
          brand: b.brands?.name, slug: b.brands?.slug, product: b.products?.name, encoded: b.tags?.[0]?.count ?? 0,
        })) });
      }
      case "tag_keys": {
        const { data: batch } = await db.from("batches").select("id, brand_id, brands(slug)").eq("id", body.batch_id).maybeSingle();
        if (!batch) return json({ error: "Batch not found" }, 404);
        const { data: existing } = await db.from("tags").select("id, status").eq("brand_id", batch.brand_id).eq("uid", uid).maybeSingle();
        if (existing && existing.status === "active") return json({ error: "This tag is already encoded. Reset it first." }, 409);
        const keys = await tagKeys(await brandKeys(batch.brand_id), uid);
        // deno-lint-ignore no-explicit-any
        return json({ uid, keys, keyVersion: 1, url: urlTemplate((batch as any).brands.slug) });
      }
      case "register": {
        const { data: batch } = await db.from("batches").select("id, brand_id").eq("id", body.batch_id).maybeSingle();
        if (!batch) return json({ error: "Batch not found" }, 404);
        const { error } = await db.from("tags").upsert({
          brand_id: batch.brand_id, batch_id: batch.id, uid, status: "active", chip: "ntag424", last_ctr: -1, scan_count: 0,
          first_scan_at: null, last_scan_at: null, encoded_at: new Date().toISOString(), encoded_by: who.user.id,
        }, { onConflict: "brand_id,uid" });
        if (error) throw error;
        return json({ ok: true });
      }
      case "register_21x": {
        const { data: batch } = await db.from("batches").select("id, brand_id, brands(slug)").eq("id", body.batch_id).maybeSingle();
        if (!batch) return json({ error: "Batch not found" }, 404);
        const { error } = await db.from("tags").upsert({
          brand_id: batch.brand_id, batch_id: batch.id, uid, status: "active", chip: "ntag21x", last_ctr: -1, scan_count: 0,
          first_scan_at: null, last_scan_at: null, encoded_at: new Date().toISOString(), encoded_by: who.user.id,
        }, { onConflict: "brand_id,uid" });
        if (error) throw error;
        // The tag fills u= with "<UID hex>x<counter hex>" (21 chars) on every read.
        // deno-lint-ignore no-explicit-any
        return json({ ok: true, url: `${TAP_BASE}?b=${(batch as any).brands.slug}&u=${"0".repeat(14)}x${"0".repeat(6)}` });
      }
      case "register_static": {
        const { data: batch } = await db.from("batches").select("id, brand_id").eq("id", body.batch_id).maybeSingle();
        if (!batch) return json({ error: "Batch not found" }, 404);
        const { data: old } = await db.from("tags").select("short_code").eq("brand_id", batch.brand_id).eq("uid", uid).maybeSingle();
        const ABC = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
        let code = old?.short_code as string | null;
        for (let i = 0; i < 5; i++) {
          if (!code) code = Array.from(globalThis.crypto.getRandomValues(new Uint8Array(6)), (b) => ABC[b % ABC.length]).join("");
          const { error } = await db.from("tags").upsert({
            brand_id: batch.brand_id, batch_id: batch.id, uid, status: "active", chip: "ultralight", short_code: code,
            last_ctr: -1, scan_count: 0, first_scan_at: null, last_scan_at: null,
            encoded_at: new Date().toISOString(), encoded_by: who.user.id,
          }, { onConflict: "brand_id,uid" });
          if (!error) return json({ ok: true, url: `${TAP_BASE}?s=${code}` });
          if (!String(error.message).includes("short_code")) throw error;
          code = null; // clash with another tag's code, try a new one
        }
        throw new Error("Could not make a unique short code");
      }
      case "reset_keys": {
        const { data: tag } = await db.from("tags").select("brand_id").eq("uid", uid).maybeSingle();
        if (!tag) return json({ error: "Tag not registered" }, 404);
        return json({ uid, keys: await tagKeys(await brandKeys(tag.brand_id), uid) });
      }
      case "mark_reset": {
        const { error } = await db.from("tags").update({ status: "reset" }).eq("uid", uid);
        if (error) throw error;
        return json({ ok: true });
      }
      case "test_create": {
        const { data: batch } = await db.from("batches").select("id, brand_id").eq("id", body.batch_id).maybeSingle();
        if (!batch) return json({ error: "Batch not found" }, 404);
        // Virtual UIDs start with 0x1D so they can never collide with real NXP tags (which start with 0x04).
        const vuid = "1D" + bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(6)));
        const { data, error } = await db.from("tags").insert({
          brand_id: batch.brand_id, batch_id: batch.id, uid: vuid, status: "active", is_virtual: true, chip: "virtual", encoded_by: who.user.id,
        }).select("id, uid").single();
        if (error) throw error;
        return json({ ok: true, tag: data });
      }
      case "test_tap": {
        const { data: tag } = await db.from("tags").select("id, uid, brand_id, is_virtual, virtual_ctr, brands(slug)").eq("id", body.tag_id).maybeSingle();
        if (!tag || !tag.is_virtual) return json({ error: "Not a virtual test tag" }, 404);
        const keys = await tagKeys(await brandKeys(tag.brand_id), tag.uid);
        const ctr = tag.virtual_ctr + 1;
        const t = await simulateTap(keys.k1, hexToBytes(keys.k2), tag.uid, ctr);
        // deno-lint-ignore no-explicit-any
        const url = `${TAP_BASE}?b=${(tag as any).brands.slug}&p=${t.p}&m=${t.m}`;
        const { error } = await db.from("tags").update({ virtual_ctr: ctr, virtual_last_url: url }).eq("id", tag.id);
        if (error) throw error;
        return json({ url, counter: ctr });
      }
      case "test_old_link": {
        const { data: tag } = await db.from("tags").select("is_virtual, virtual_last_url").eq("id", body.tag_id).maybeSingle();
        if (!tag || !tag.is_virtual) return json({ error: "Not a virtual test tag" }, 404);
        if (!tag.virtual_last_url) return json({ error: "Tap this test tag once first" }, 409);
        return json({ url: tag.virtual_last_url });
      }
      default:
        return json({ error: "Unknown action" }, 400);
    }
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
