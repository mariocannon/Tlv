package nz.cardforge.desfire;

import java.util.Arrays;

/** Small byte helpers. */
public final class Hex {
    private Hex() {}

    private static final char[] DIGITS = "0123456789ABCDEF".toCharArray();

    public static byte[] decode(String s) {
        String clean = s.replaceAll("[\\s:\\-]", "");
        if (clean.startsWith("0x") || clean.startsWith("0X")) clean = clean.substring(2);
        if (clean.length() % 2 != 0) throw new IllegalArgumentException("Odd-length hex");
        byte[] out = new byte[clean.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(clean.charAt(i * 2), 16);
            int lo = Character.digit(clean.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Bad hex: " + s);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static String encode(byte[] b) {
        if (b == null) return "";
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            c[i * 2] = DIGITS[(b[i] >> 4) & 0xF];
            c[i * 2 + 1] = DIGITS[b[i] & 0xF];
        }
        return new String(c);
    }

    public static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    public static byte[] slice(byte[] b, int from, int to) {
        return Arrays.copyOfRange(b, from, to);
    }

    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("xor length mismatch");
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    public static byte[] rotateLeft(byte[] b) {
        byte[] out = new byte[b.length];
        System.arraycopy(b, 1, out, 0, b.length - 1);
        out[b.length - 1] = b[0];
        return out;
    }

    /** 3-byte little-endian (DESFire AIDs, offsets, lengths). */
    public static byte[] le24(int v) {
        return new byte[] {(byte) v, (byte) (v >> 8), (byte) (v >> 16)};
    }

    public static int fromLe24(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8) | ((b[off + 2] & 0xFF) << 16);
    }

    /** Pad with zero bytes up to a multiple of blockSize (DESFire style; no padding if already aligned). */
    public static byte[] zeroPad(byte[] b, int blockSize) {
        int n = ((b.length + blockSize - 1) / blockSize) * blockSize;
        if (n == 0) n = blockSize;
        return Arrays.copyOf(b, n);
    }
}
