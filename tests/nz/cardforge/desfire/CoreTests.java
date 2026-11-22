package nz.cardforge.desfire;

import java.security.SecureRandom;
import java.util.Arrays;

/** Plain-Java test runner (no JUnit needed): ./run-tests.sh */
public final class CoreTests {
    static int passed = 0;

    static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        passed++;
        System.out.println("  ok  " + name);
    }

    static void eqHex(byte[] got, String want, String name) {
        boolean ok = Hex.encode(got).equalsIgnoreCase(want);
        if (!ok) System.out.println("      got  " + Hex.encode(got) + "\n      want " + want);
        check(ok, name);
    }

    interface Body { void run() throws Exception; }

    static void expectError(Body b, String name) {
        try {
            b.run();
        } catch (Exception e) {
            System.out.println("      (expected) " + e.getMessage());
            check(true, name);
            return;
        }
        check(false, name);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Primitives");
        eqHex(Crc32Desfire.compute("123456789".getBytes("US-ASCII")), "D9C60B34", "CRC32 (JAMCRC, LE) of 123456789");

        KeyCipher rfc = KeyCipher.aes(Hex.decode("2b7e151628aed2a6abf7158809cf4f3c"));
        eqHex(rfc.cmac(new byte[16], new byte[0]), "bb1d6929e95937287fa37d129b756746", "AES-CMAC RFC4493 #1 (empty)");
        eqHex(rfc.cmac(new byte[16], Hex.decode("6bc1bee22e409f96e93d7e117393172a")), "070a16b46b4d4144f79bdd9dd04a287c", "AES-CMAC RFC4493 #2 (16 bytes)");
        eqHex(rfc.cmac(new byte[16], Hex.decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411")),
                "dfa66747de9ae63030ca32611497c827", "AES-CMAC RFC4493 #3 (40 bytes)");

        eqHex(KeyDiversifier.aes128(Hex.decode("00112233445566778899AABBCCDDEEFF"),
                        KeyDiversifier.input(Hex.decode("04782E21801D80"), 0xF54230, Hex.decode("4E585020416275"))),
                "A8DD63A3B89D54B37CA802473FDA9175", "AN10922 AES-128 diversification (NXP example)");

        System.out.println("Credential / ICT config");
        Credential c34 = new Credential(Credential.Format.W34, 123, 4567);
        byte[] f = c34.toFile(32);
        eqHex(Arrays.copyOf(f, 7), "007B11D7434603", "W34 file layout: site,card at byte 0 + CF marker");
        check(Credential.parse(f).card == 4567, "parse W34");
        check(Credential.Format.W34.ictFormatString().equals("%16s%16c"), "ICT format string W34");
        CardProfile ict = new CardProfile();
        ict.readKey = Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        check(ict.ictKeyslotTlv().equals("0311FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF02"), "ICT keyslot TLV matches guide example layout");
        ict.format = Credential.Format.W34;
        check(ict.ictFormatHex().equals("2531367325313663"), "ICT format ASCII hex");
        expectError(() -> new Credential(Credential.Format.W26, 256, 1), "W26 rejects site > 255");

        SecureRandom rnd = new SecureRandom();
        for (DesfireSession.Comm comm : DesfireSession.Comm.values()) {
            for (boolean div : new boolean[] {false, true}) {
                for (boolean lock : new boolean[] {false, true}) {
                    String tag = comm + (div ? " +diversify" : "") + (lock ? " +lockPICC" : "");
                    System.out.println("End-to-end: " + tag);
                    endToEnd(CardProfile.generate(rnd), comm, div, lock, tag);
                }
            }
        }
        System.out.println("\nAll " + passed + " checks passed.");
    }

    static void endToEnd(CardProfile p, DesfireSession.Comm comm, boolean div, boolean lock, String tag) throws Exception {
        p.comm = comm;
        p.diversify = div;
        p.lockPicc = lock;
        DesfireSim card = new DesfireSim();
        StringBuilder log = new StringBuilder();
        CardEncoder enc = new CardEncoder(new DesfireSession(card), p, card.uid, m -> log.append(m).append('\n'));

        Credential want = new Credential(Credential.Format.W34, 123, 4567);
        enc.encode(want, false);
        check(card.apps.containsKey(p.aid), tag + ": app created");
        DesfireSim.App app = card.apps.get(p.aid);
        check(Arrays.equals(app.keys[1].k, p.cardKey(p.readKey, card.uid, p.aid)), tag + ": read key on card");
        check(div != Arrays.equals(app.keys[1].k, p.readKey), tag + ": diversification " + (div ? "applied" : "off"));
        check(card.piccKey.aes == lock, tag + ": PICC key " + (lock ? "locked to AES" : "left default"));

        // Simulate the ICT reader: fresh session, auth with key 1, read from offset 0.
        DesfireSession reader = new DesfireSession(card);
        reader.selectApplication(p.aid);
        reader.authenticateAes(1, p.cardKey(p.readKey, card.uid, p.aid));
        byte[] first4 = reader.readData(p.fileNo, 0, 4, comm);
        eqHex(first4, "007B11D7", tag + ": reader sees site 123 / card 4567 at offset 0");

        expectError(() -> {
            DesfireSession r = new DesfireSession(card);
            r.selectApplication(p.aid);
            r.authenticateAes(1, new byte[16]);
        }, tag + ": wrong read key rejected");

        expectError(() -> {
            DesfireSession r = new DesfireSession(card);
            r.selectApplication(p.aid);
            r.authenticateAes(1, p.cardKey(p.readKey, card.uid, p.aid));
            r.writeData(p.fileNo, 0, new byte[4], comm);
        }, tag + ": read key cannot write");

        expectError(() -> enc.encode(want, false), tag + ": refuses to re-encode without overwrite");
        enc.encode(new Credential(Credential.Format.W34, 9, 42), true);
        check(enc.verify().card == 42, tag + ": overwrite works");

        enc.wipe();
        check(card.apps.isEmpty(), tag + ": wipe deletes app");
        check(!card.piccKey.aes && Arrays.equals(card.piccKey.k, new byte[16]) && card.piccSettings == 0x0F, tag + ": wipe restores factory PICC");
    }
}
