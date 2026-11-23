# CardForge: custom-key DESFire & MIFARE Classic cards for ICT readers

An Android app that encodes MIFARE DESFire EV1/EV2/EV3 cards with **your own AES keys** from the phone. It also prints the exact Protege Config App settings, including the **Keyslot hex TLV**, so your ICT reader (OSDP output) can read the cards.

## How it fits together

```
Phone (CardForge)                      Card (DESFire)                         ICT reader
-----------------                      --------------                         ----------
holds 4 AES keys  --- encodes --->     App F5AC01, 3 AES keys                 Keyslot 2 = read key
                                         key0 app master (phone only)          Access Cred slot 7:
                                         key1 READ  -----------------------      App F5AC01, file 1, key 1
                                         key2 WRITE (phone only)               Format slot 6: %16s%16c
                                       File 1 (32 bytes, encrypted comm)       Linkage slot 6 -> OSDP out
                                         [site][card]'C''F'[fmt] 00...
```

* The reader only ever gets **key 1, the read key**. Key 1 can read the file but not write it, so a stolen reader key can't be used to create new cards.
* The file uses **encrypted communication**, so the credential is never sent in the clear over the air.
* Card data starts at byte 0, because ICT format strings read from the start of the file.

## ICT reader programming (Protege Config App)

In the app, open **Keys → ICT reader config + keyslot TLV**. It shows these values filled in with your own keys:

1. **Hex TLV** (loads the AES read key): `0311<32 hex read key>02`. Type 03, length 0x11 (17 bytes), key, then keyslot 2.
2. **Access Credentials**: Slot 7 · Mifare DESFire · App ID `F5AC01` · AES Keyslot 2 · File Number 1 · Key Number 1 · No diversification
3. **Custom Card Format Slots**: Slot 6 · Format `2531367325313663` (= `%16s%16c` for the default 34-bit style)
4. **Card Linkages**: Linkage slot 6 · Flags: none · Keyslot 2 · Access Credential slot 7 · Format slot 6
5. **Output Mode**: OSDP
6. tSec readers only, with EV2/EV3 cards: Hex TLV `180106` (ISO14443 gain 6). TSL readers don't need this.

Power-cycle the reader and apply the config within 2 minutes.

| Format | Card data | ICT format string | Hex |
|---|---|---|---|
| 26-bit style | 8-bit site + 16-bit card | `%8s%16c` | `25387325313663` |
| 34-bit style (default) | 16-bit site + 16-bit card | `%16s%16c` | `2531367325313663` |
| 48-bit | 16-bit site + 32-bit card | `%16s%32c` | `2531367325333263` |

## First test (do this before issuing real cards)

1. Install the APK and open **Keys**. Tap **Generate new random keys**, then **Save**.
2. Leave **diversification OFF** and **lock card master key OFF** for the first test.
3. **Encode** a blank card (e.g. site 1, card 1), then tap **Verify**: it should show *Valid ✔*.
4. Program the reader with the generated config and present the card. Protege should log site 1 / card 1.
5. If the reader doesn't read the card, try these in order:
   * App ID byte order: enter `01ACF5` (reversed) in the reader's Access Credential App ID field.
   * Card Linkage flags: some config app versions may insist on a flag. CardForge doesn't use ICT's extra "AES 256 data layer"; tell me if you need it.
   * For EV2/EV3 cards on a tSec reader, apply the `180106` gain TLV.
6. **Wipe** returns a test card to factory state so you can reuse it.

### Optional hardening once the basics work

* **AV2 diversification**: every card gets its own keys, derived from its UID (NXP AN10922). Turn it on in both the app and the reader ("AV2 Diversification"). ICT doesn't document its AV2 system identifier, so leave the system ID blank. If cards then fail to read, ICT's variant uses different input, so switch diversification off again.
* **Lock card master key**: replaces the factory DES card key with your AES key, so nobody can delete your application. **Wipe** reverses it.

## MIFARE Classic option

Under **Keys → Card type**, choose **MIFARE Classic 1K/4K** and tap **Generate new random keys** (this only changes the Classic keys). Then **Save**.

* Card layout: sector 1 by default. Block 4 holds the credential (same byte layout as DESFire), blocks 5–6 are zeroed, and block 7 is the trailer `KeyA | 78 77 88 69 | KeyB`.
* **Key A = read key** goes into the reader. **Key B = write key** stays on the phone. Access bits `78 77 88` mean Key A can read but never write data or change keys.
* ICT config (the app shows it filled in):
  1. Hex TLV `0307<12 hex Key A>02` (type 03, length 07: 6-byte key + keyslot)
  2. Access Credentials: Slot 7 · Mifare Classic · Block 4 · Key Type A · Keyslot 2 · no Diversify Key flag
  3. Format slot, Card Linkage, OSDP: same as DESFire
* **Wipe** restores the factory trailer (`FFFFFFFFFFFF FF078069 FFFFFFFFFFFF`) so the card can be reused.
* **Phone support:** Android can only do MIFARE Classic if the phone has an NXP NFC chip. Many Samsung and Pixel phones can't. If the app says it can't open the card as Classic, that's the phone, not the card.
* **Security:** Classic's Crypto1 is broken, and cards can be cloned with cheap tools in minutes. Use it for legacy sites or low-risk doors. Use DESFire anywhere security matters.

## Security notes (keys on the phone)

* Keys are stored encrypted with a non-exportable Android Keystore key. Backups are disabled, and screenshots of the app are blocked.
* Anyone who has the phone unlocked can still encode cards. If the phone is lost, generate new keys and re-issue all cards. A later version could move keys to a backend or an SAM.
* **Export profile** puts every key in plain text. Only use it to set up a second phone, and keep the export in a password manager.

## Building

* Pushing to GitHub runs `.github/workflows/build.yml`. It runs the crypto tests, then builds `cardforge-debug-apk` (download it from the Actions run).
* Locally: Android Studio → Open folder, or `gradle assembleDebug`.
* Crypto tests without Android: `./run-tests.sh`. These cover the RFC 4493 CMAC vectors, the NXP AN10922 vector, CRC32, and the full encode / reader-read / wipe flow against a simulated DESFire card in every comm mode.

## Code map

* `desfire/DesfireSession.java`: DESFire native commands, AES + ISO auth, EV1 secure messaging
* `desfire/CardEncoder.java`: encode / verify / wipe flows
* `desfire/CardProfile.java`: keys, AID, file settings, ICT config generator
* `desfire/Credential.java`: on-card data layout
* `desfire/KeyDiversifier.java`: AN10922 AES-128
* `desfire/ClassicEncoder.java` + `AndroidClassic.java`: MIFARE Classic encode / verify / wipe
* `MainActivity.java`, `ProfileStore.java`: Android UI, NFC, Keystore storage

## Verity mode: NTAG 424 DNA product tags

CardForge also encodes **Verity** anti-counterfeit tags. These are NXP NTAG 424 DNA stickers that shoppers tap with any phone to check a product is genuine, with no app needed. Open it from the **Verity product tags** button on the main screen.

| Piece | Where |
| --- | --- |
| Encode / Check / Reset screen | `app/src/main/java/nz/cardforge/verity/` |
| NTAG 424 DNA EV2 secure messaging + SUN setup | `app/src/main/java/nz/cardforge/ntag/` |
| Server: verify + encoder edge functions, shared crypto | `supabase/functions/` |
| Shopper tap page, staff dashboard | `docs/` (GitHub Pages) |
| Step-by-step test and demo guide | [`docs/VERITY_MVP.md`](docs/VERITY_MVP.md) |

How a tag is set up: K0 app master (per tag), K1 SUN meta-read (per brand), K2 SUN MAC (per tag), K3/K4 locked (per tag). Per-tag keys are AN10922-diversified from brand master keys held in Supabase Vault. The NDEF file holds `https://mariocannon.github.io/Tlv/t/?b=<brand>&p=<encrypted UID+counter>&m=<MAC>`, which the tag rewrites on every tap.

`./run-tests.sh` checks the crypto against NXP's AN12196 and AN10922 worked examples and runs encode → tap → reset on a simulated NTAG 424 DNA. With Node 22+, it also confirms a Java-encoded tap verifies with the server's TypeScript code.
