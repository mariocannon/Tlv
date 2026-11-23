# CardForge Pool (web MVP)

Installers and site owners manage pools of site-code + card-number credentials for ICT sites.
Static site (no build step) + Supabase project **CardForge Pool** (`whgdqbplitaacpxyogfn`, Sydney).

## Deploy on Vercel (one-off, ~2 min)

1. Vercel → **Add New → Project** → import `mariocannon/Tlv`.
2. **Root Directory:** `web` · **Framework Preset:** Other · leave Build/Output empty.
3. Deploy. Note the URL (e.g. `https://tlv-xxxx.vercel.app`).
4. Supabase → CardForge Pool → **Authentication → URL Configuration**:
   - **Site URL:** your Vercel URL
   - **Redirect URLs:** add the same URL
   (Confirmation and password-reset emails link here.)

## First run

1. Open the site → **Create an account** → confirm the email → sign in.
2. "Name your business" → creates your installer account.
3. **Add site**: name, site code (must match the code you encode with CardForge), format, pool size.
4. **Site owners** tab → add the owner's email. They create an account with that email and only see their site.

## Rules the database enforces (not just the UI)

- Every write goes through role-checked functions; clients can't edit tables directly.
- Assign takes never-used numbers first, recycled ones last.
- Unassign → **quarantine**. A number only returns to the pool after *both* "removed from Protege" and "card wiped / phone cleared" are ticked.
- Lost/stolen → **retired**, never reissued.
- Only installers can top up pools, add sites or manage owners; owners can request a top-up.
- Every action is written to the site's Activity log.

## Before real customers

- **Email:** Supabase's built-in sender is rate-limited (a few emails per hour). Set custom SMTP (e.g. Amazon SES) under Authentication → Emails.
- **Panel sync:** panel changes are manual steps for now; a Protege GX API sync would remove them.
- **Phone invites:** phones get their site/card typed in by hand; the CardForge app claiming invites is the next step.

Database schema and functions: `../supabase/migrations/`.
