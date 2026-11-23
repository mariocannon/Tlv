# Verity MVP: test with real tags and demo it

This is the working MVP of Verity. Staff encode NXP **NTAG 424 DNA** tags with CardForge. Anyone taps a tag with their phone and sees whether the product is genuine, and every tap shows up live on the dashboard.

| Part | Link |
| --- | --- |
| Staff dashboard | https://mariocannon.github.io/tlv/dashboard/ |
| Shopper tap page (opened by the tag) | https://mariocannon.github.io/tlv/t/ |
| About page | https://mariocannon.github.io/tlv/ |
| Server | Supabase project **Verity** (`emcuwvuouggvdwnowlwr`, Sydney) |
| App | CardForge APK from GitHub Actions, branch `verity` |

---

## 1. What you need

- An **Android phone with NFC**, to run CardForge.
- **Blank NTAG 424 DNA tags.** Stickers are fine; get 5–10 for testing. Other NFC tags (NTAG 213/215/216, DESFire) won't work.
- Any second phone (iPhone or Android) to play the shopper.

## 2. One-time setup (5 minutes)

1. Open the **dashboard** and tap **Create account** with your email and a password of 8+ characters.
   **The first account ever created becomes the owner/staff**, so do this before sharing the link.
2. Confirm the email Supabase sends you, then **Sign in**.
3. You'll see the demo brand **Kōwhai Mānuka Co. (demo)** with batch **B-0001**. You can also add your own brand and batch at the bottom of the dashboard (e.g. a real local brand you want to pitch).

## 3. Install CardForge

1. On GitHub, open **mariocannon/tlv → Actions → Build APK**, pick the latest run on branch **verity**, and download **cardforge-debug-apk**.
2. Unzip it, copy the `.apk` to your Android phone and install it. Allow "install unknown apps" when asked.
3. Open CardForge and tap **Verity product tags (NTAG 424 DNA) →** at the top.
4. Sign in with the same email and password as the dashboard.

## 4. Encode a tag

1. Tap **Refresh batches** and pick **Kōwhai Mānuka Co. (demo) · … · B-0001**.
2. Stay on **Encode** and hold a blank NTAG 424 DNA tag flat against the back of the phone until the status changes. This takes about 1–2 seconds.
3. You should see **Encoded ✔ and verified** and the product name. The log shows each step:
   - the keys are fetched for this tag only
   - the URL, tap-to-verify settings and 5 AES keys are written
   - the tag is registered
   - the tag is read back and checked by the server
4. The tag now appears in the dashboard's **Tags** table, and its check appears in **Latest scans** as a *Staff check*.

## 5. Tap it like a shopper

Hold the tag to any phone with NFC on. On iPhone, hold it near the top edge with the screen unlocked; most Android phones read it near the middle of the back.

- The browser opens **"It's genuine"** with the product details and how many times it's been checked.
- The dashboard shows a new **Genuine** shopper scan within 5 seconds, with the city taken from the phone's time zone.

## 6. Show it catching fakes

| Try this | What happens |
| --- | --- |
| **Copied link.** After a tap, copy the page's URL (Share → Copy) and open it again, or send it to someone else to open | **"This may not be genuine"** (the code was already used). The dashboard raises a **High** alert: *Copied link reused*. |
| **Same tag, two places.** Tap the tag, then within an hour tap it with a phone set to another time zone (e.g. Sydney) | Still genuine, but a **Medium** alert: *scanned in Auckland and Sydney within an hour*. |
| **Cancelled tag.** Press **Cancel** next to the tag in the dashboard, then tap it | **"This may not be genuine"**: the brand has cancelled this tag. Press **Restore** to undo. |
| **Tampered link.** Change one character of `m=` in a tap URL and open it | **Blocked**: the signature doesn't match. |
| **Different tag.** Tap a tag that was never encoded by Verity | Nothing opens, because a blank tag has no Verity link. |

In CardForge, **Check** shows the server's reasoning for any tag: verdict, counter, last accepted counter and why. **Open last tap in browser** opens the shopper page for the URL just read. That link has now been used once, so opening it a second time shows the copied-link warning, which is a handy way to demo replay.

## 7. Reuse test tags

**Reset** tab → tick **Armed** → tap the tag. It goes back to factory keys and can be encoded again, into any batch.

## 8. A 3-minute demo for someone else

1. Hand them the tagged product and say: "Tap it with your phone." They see **It's genuine**.
2. Show the dashboard on your laptop: their scan is already there, with their city.
3. Text them the link that opened and say: "Pretend you're a counterfeiter and you've copied the tag. Open that." They see the warning, and a **High** alert appears on the dashboard.
4. Explain why: every tap makes a new one-time code signed with a key that never leaves the chip. A copied code or a cloned sticker fails on its first tap. QR codes can't do this.

## 9. Troubleshooting

| Message | Fix |
| --- | --- |
| *This tag isn't blank (factory key refused)* | It's already encoded. Use **Reset** if it's one of yours. If Reset can't find it, it was encoded by something else. |
| *Tag moved away mid-write* | Hold it still and tap again. If Encode now says "not blank", Reset it first. |
| *This tag is already encoded. Reset it first.* | The server already has this tag as active. Reset it, or cancel it on the dashboard. |
| *This isn't an NTAG 424 DNA* | Wrong tag type. You need NTAG 424 DNA. |
| *This account is not Verity staff* | Only the first account is staff automatically. To add someone, run `insert into staff (user_id) select id from auth.users where email = 'them@example.com';` in the Supabase SQL editor. |
| Phone doesn't open the page on tap | Make sure NFC is on (Android), the screen is unlocked, and the tag touches the phone's antenna area. |

## 10. What's real and what's MVP-only

**Real (production-grade):**
- NTAG 424 DNA tap-to-verify messages, with AES-encrypted UID and counter plus a per-tap signature.
- A unique AES key per tag (NXP AN10922), with brand master keys encrypted in Supabase Vault.
- Atomic replay protection.
- All crypto tested against NXP's published AN12196 and AN10922 examples, both in the Java app and in the TypeScript server.

**MVP shortcuts to fix before paying customers:**
- Keys go to the phone over HTTPS for one tag at a time. Production should wrap them to a per-session device key, or encode with a hardware SAM.
- Brand keys sit in Supabase Vault, not a hardware security module.
- The tap page is hosted on GitHub Pages under `mariocannon.github.io/tlv`. Move it to your own short domain before real launches; tags encoded now keep this URL forever, so use test tags only.
- City comes from the phone's time zone, not IP geolocation.
- The dashboard is staff-only. There are no brand logins or billing yet.
- The `selftest` brand and its one tag exist only for automated server tests and are hidden from the app.

## 11. Developer notes

- `./run-tests.sh` runs everything: CardForge's original 159 checks, 19 NTAG 424 DNA checks (EV2 session keys and the SUN example from AN12196, then encode → tap → reset on a simulated tag), the server's TypeScript crypto tests, and a cross-check that a Java-encoded tap verifies with the server code.
- The edge functions are `supabase/functions/verify` (public) and `supabase/functions/encoder` (staff JWT). The schema is in `supabase/migrations/`.
- Tag layout: K0 app master (per tag), K1 SUN meta-read (per brand), K2 SUN MAC (per tag), K3/K4 locked. The NDEF file is read-free and write-K0, with UID + counter mirrored inside encrypted PICCData and a MAC over an empty input.
