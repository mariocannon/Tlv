package nz.cardforge.ntag;

import java.io.FileWriter;
import java.nio.charset.StandardCharsets;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.Hex;
import nz.cardforge.desfire.KeyDiversifier;

/** NTAG 424 DNA / Verity tests (plain Java, no Android): ./run-tests.sh */
public final class Ntag424Tests {
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

    static final String TEMPLATE = "https://mariocannon.github.io/tlv/t/?b=demo&p=00000000000000000000000000000000&m=0000000000000000";

    public static void main(String[] args) throws Exception {
        byte[] zero = new byte[16];

        System.out.println("NXP AN12196 worked examples");
        byte[][] sk = Ntag424Session.sessionKeys(zero, Hex.decode("13C5DB8A5930439FC3DEF9A4C675360F"), Hex.decode("B9E2FC789B64BF237CCCAA20EC7E6E48"));
        eqHex(sk[0], "1309C877509E5A215007FF0ED19CA564", "EV2 SesAuthENCKey");
        eqHex(sk[1], "4C6626F5E72EA694202139295C7A7FC7", "EV2 SesAuthMACKey");
        SunVerifier.Result sun = SunVerifier.verify(zero, zero, "EF963FF7828658A599F3041510671E88", "94EED9EE65337086");
        check(sun.ok && "04DE5F1EACC040".equals(sun.uid) && sun.counter == 61, "SUN: PICCData decrypt + SDM MAC (UID 04DE5F1EACC040, ctr 61)");
        check(!SunVerifier.verify(zero, zero, "EF963FF7828658A599F3041510671E88", "94EED9EE65337087").ok, "SUN: tampered MAC rejected");

        System.out.println("NDEF layout + file settings");
        Ntag424Encoder.Layout l = Ntag424Encoder.layout(TEMPLATE);
        String file = new String(l.file, StandardCharsets.ISO_8859_1);
        check(file.substring(l.piccOffset, l.piccOffset + 32).equals("00000000000000000000000000000000"), "PICCData offset points at the 32-char placeholder");
        check(file.substring(l.macOffset, l.macOffset + 16).equals("0000000000000000"), "MAC offset points at the 16-char placeholder");
        check(((l.file[0] & 0xFF) << 8 | (l.file[1] & 0xFF)) == l.file.length - 2, "NLEN matches record length");
        byte[] fs = Ntag424Encoder.sdmSettings(l);
        check(fs.length == 15 && fs[0] == 0x40 && fs[3] == (byte) 0xC1, "SDM file settings: 15 bytes, SDM on, UID+ctr mirror ASCII");

        System.out.println("Encode -> tap -> reset on a simulated NTAG 424 DNA");
        byte[] uid = Hex.decode("04A35B128C6E80");
        // Same per-tag derivation the server uses: AN10922(master, UID || "VRTY" || keyNo).
        byte[] cfg = Hex.decode("146BFA205D4A7B8D67D058375E7C530D"), mac = Hex.decode("84510A3835EBA53A9510526EA7C738A0");
        byte[] meta = Hex.decode("1D44ACBD631C0337CE8DBD74502336B0");
        Ntag424Encoder.TagKeys keys = new Ntag424Encoder.TagKeys(div(cfg, uid, 0), meta, div(mac, uid, 2), div(cfg, uid, 3), div(cfg, uid, 4));

        Ntag424Sim tag = new Ntag424Sim(uid);
        Ntag424Encoder enc = new Ntag424Encoder(new Ntag424Session(tag));
        check(enc.isFactory(), "blank tag reports factory keys");
        enc.encode(keys, TEMPLATE);
        check(java.util.Arrays.equals(tag.keys[0], keys.k[0]) && java.util.Arrays.equals(tag.keys[2], keys.k[2]), "keys written to the tag");
        check(tag.fileOption == 0x40 && tag.ar1 == 0xE0, "NDEF file: SUN on, write locked to K0");
        check(!enc.isFactory(), "encoded tag no longer accepts the factory key");

        String url1 = enc.readUrl(), url2 = enc.readUrl();
        check(url1.startsWith("https://mariocannon.github.io/tlv/t/?b=demo&p="), "tap URL keeps the template: " + url1);
        String[] p1 = SunVerifier.params(url1), p2 = SunVerifier.params(url2);
        SunVerifier.Result r1 = SunVerifier.verify(meta, keys.k[2], p1[0], p1[1]);
        SunVerifier.Result r2 = SunVerifier.verify(meta, keys.k[2], p2[0], p2[1]);
        check(r1.ok && r1.uid.equals("04A35B128C6E80") && r1.counter == 1, "1st tap verifies, counter 1");
        check(r2.ok && r2.counter == 2 && !p1[0].equals(p2[0]), "2nd tap verifies with a new code, counter 2");
        check(!SunVerifier.verify(meta, div(mac, Hex.decode("04000000000000"), 2), p2[0], p2[1]).ok, "a cloned tag (wrong per-tag key) fails");

        try (FileWriter w = new FileWriter("build/core-tests/crossk.json")) {
            w.write("{\"meta\":\"" + Hex.encode(meta) + "\",\"mac\":\"" + Hex.encode(mac) + "\",\"cfg\":\"" + Hex.encode(cfg)
                    + "\",\"uid\":\"04A35B128C6E80\",\"url\":\"" + url2 + "\",\"k0\":\"" + Hex.encode(keys.k[0]) + "\"}");
        }

        boolean refused = false;
        try { enc.encode(keys, TEMPLATE); } catch (DesfireException e) { refused = true; }
        check(refused, "re-encoding an encoded tag is refused (factory key no longer works)");

        enc.reset(keys);
        check(enc.isFactory() && tag.fileOption == 0x00 && tag.ar1 == 0xEE, "reset returns the tag to factory keys and plain file");
        enc.encode(keys, TEMPLATE);
        String[] p3 = SunVerifier.params(enc.readUrl());
        SunVerifier.Result r3 = SunVerifier.verify(meta, keys.k[2], p3[0], p3[1]);
        check(r3.ok, "a reset tag can be encoded again");

        System.out.println("\n" + passed + " NTAG 424 DNA tests passed");
    }

    static byte[] div(byte[] master, byte[] uid, int keyNo) {
        return KeyDiversifier.aes128(master, Hex.concat(uid, "VRTY".getBytes(StandardCharsets.US_ASCII), new byte[] {(byte) keyNo}));
    }
}
