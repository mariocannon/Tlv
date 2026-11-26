# Moving Verity to its own domain

Do this **before encoding real NTAG 424 DNA tags**: the link is written into each tag and locked.
(GitHub does redirect the old `mariocannon.github.io/Tlv/...` addresses to the custom domain, so
test tags made before the move keep working, but real tags should carry the real domain.)

Example below uses `verity.co.nz`; swap in the domain you buy.

1. **Buy the domain** (any NZ registrar).
2. **DNS** at the registrar:
   - Apex `verity.co.nz`: four `A` records → `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - `www`: `CNAME` → `mariocannon.github.io`
3. **GitHub** → repo Tlv → Settings → Pages → Custom domain: `verity.co.nz` → Save, then tick **Enforce HTTPS** once the certificate is ready (can take up to an hour). This adds `docs/CNAME`.
4. **Rebuild the landing page at the root**:
   `cd site && SITE_URL=https://verity.co.nz SITE_BASE=/ npm run pages`, then commit and push.
5. **Server tag links**: set the Supabase Edge Function secret `VERITY_TAP_BASE=https://verity.co.nz/t/`
   (Supabase dashboard → Edge Functions → Secrets). New encodes then use the new domain.
6. **Brand links**: update any brand `link_url` that points at the old address.
7. **Supabase Auth** → URL configuration: set Site URL to `https://verity.co.nz/dashboard/`.
8. **CardForge app**: change `VerityApi.SITE` to `https://verity.co.nz/` and push to build a new APK.

Nothing else needs changing: the tap page and dashboard use relative paths, and the tap page shows
whatever address it's served from in its "Real checks only open at …" line.
