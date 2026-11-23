package nz.cardforge.ntag;

import java.util.Arrays;

import nz.cardforge.desfire.Hex;
import nz.cardforge.desfire.KeyCipher;

/**
 * Checks an NTAG 424 DNA SUN message (encrypted PICCData + truncated SDM MAC), per AN12196.
 * The server does the real check; this copy lets the tests and the app's QC view explain results.
 */
public final class SunVerifier {
    private SunVerifier() {}

    public static final class Result {
        public final boolean ok;
        public final String uid;
        public final int counter;
        public final String reason;
        Result(boolean ok, String uid, int counter, String reason) {
            this.ok = ok; this.uid = uid; this.counter = counter; this.reason = reason;
        }
    }

    /** Session MAC key = CMAC(fileReadKey, 3CC3 0001 0080 || UID || ctr LE). */
    public static byte[] sessionMacKey(byte[] fileReadKey, byte[] uid, byte[] ctrLe) {
        return KeyCipher.aes(fileReadKey).cmac(new byte[16], Hex.concat(Hex.decode("3CC300010080"), uid, ctrLe));
    }

    /** SDM MAC over an empty MAC input, truncated to the odd bytes. */
    public static byte[] mac(byte[] fileReadKey, byte[] uid, byte[] ctrLe) {
        byte[] ses = sessionMacKey(fileReadKey, uid, ctrLe);
        return Ntag424Session.truncateMac(KeyCipher.aes(ses).cmac(new byte[16], new byte[0]));
    }

    public static Result verify(byte[] metaReadKey, byte[] fileReadKey, String pHex, String mHex) {
        if (pHex == null || mHex == null || !pHex.matches("[0-9A-Fa-f]{32}") || !mHex.matches("[0-9A-Fa-f]{16}")) {
            return new Result(false, null, -1, "Link is missing its code");
        }
        byte[] plain = KeyCipher.aes(metaReadKey).decryptCbc(new byte[16], Hex.decode(pHex));
        if ((plain[0] & 0xFF) != 0xC7) return new Result(false, null, -1, "PICCData did not decrypt (wrong brand key)");
        byte[] uid = Arrays.copyOfRange(plain, 1, 8);
        byte[] ctrLe = Arrays.copyOfRange(plain, 8, 11);
        int ctr = Hex.fromLe24(ctrLe, 0);
        boolean macOk = Arrays.equals(mac(fileReadKey, uid, ctrLe), Hex.decode(mHex));
        return new Result(macOk, Hex.encode(uid), ctr, macOk ? "Signature valid" : "Signature does not match");
    }

    /** Pulls p= and m= out of a tap URL. Returns {p, m} or nulls. */
    public static String[] params(String url) {
        String p = null, m = null;
        int q = url.indexOf('?');
        if (q >= 0) {
            for (String kv : url.substring(q + 1).split("&")) {
                if (kv.startsWith("p=")) p = kv.substring(2);
                else if (kv.startsWith("m=")) m = kv.substring(2);
            }
        }
        return new String[] {p, m};
    }
}
