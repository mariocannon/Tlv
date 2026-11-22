package nz.cardforge.desfire;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** CBC block cipher wrapper for AES-128 and 2K3DES (DESFire key types used here). */
public final class KeyCipher {
    public enum Type { AES, TDES }

    private final Type type;
    private final SecretKeySpec key;

    private KeyCipher(Type type, byte[] keyBytes) {
        this.type = type;
        if (type == Type.AES) {
            if (keyBytes.length != 16) throw new IllegalArgumentException("AES key must be 16 bytes");
            this.key = new SecretKeySpec(keyBytes.clone(), "AES");
        } else {
            if (keyBytes.length != 16) throw new IllegalArgumentException("2K3DES key must be 16 bytes");
            byte[] k24 = Hex.concat(keyBytes, Arrays.copyOf(keyBytes, 8)); // K1 K2 K1
            this.key = new SecretKeySpec(k24, "DESede");
        }
    }

    public static KeyCipher aes(byte[] key) { return new KeyCipher(Type.AES, key); }

    public static KeyCipher tdes(byte[] key16) { return new KeyCipher(Type.TDES, key16); }

    public Type type() { return type; }

    public int blockSize() { return type == Type.AES ? 16 : 8; }

    private String transform() { return type == Type.AES ? "AES/CBC/NoPadding" : "DESede/CBC/NoPadding"; }

    public byte[] encryptCbc(byte[] iv, byte[] data) { return run(Cipher.ENCRYPT_MODE, iv, data); }

    public byte[] decryptCbc(byte[] iv, byte[] data) { return run(Cipher.DECRYPT_MODE, iv, data); }

    private byte[] run(int mode, byte[] iv, byte[] data) {
        if (data.length % blockSize() != 0) throw new IllegalArgumentException("Data not block aligned");
        try {
            Cipher c = Cipher.getInstance(transform());
            c.init(mode, key, new IvParameterSpec(iv));
            return c.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Last cipher block of a buffer (used as next IV). */
    public byte[] lastBlock(byte[] cipherText) {
        return Arrays.copyOfRange(cipherText, cipherText.length - blockSize(), cipherText.length);
    }

    /**
     * CMAC (NIST SP 800-38B) with a caller supplied starting IV, as DESFire EV1 chains its IV through CMACs.
     * Returns the full block-size MAC.
     */
    public byte[] cmac(byte[] iv, byte[] msg) {
        int bs = blockSize();
        int rb = bs == 16 ? 0x87 : 0x1B;
        byte[] l = encryptCbc(new byte[bs], new byte[bs]);
        byte[] k1 = shiftLeft(l, rb);
        byte[] k2 = shiftLeft(k1, rb);
        boolean complete = msg.length > 0 && msg.length % bs == 0;
        byte[] m;
        if (complete) {
            m = msg.clone();
            xorInto(m, m.length - bs, k1);
        } else {
            int n = (msg.length / bs + 1) * bs;
            m = Arrays.copyOf(msg, n);
            m[msg.length] = (byte) 0x80;
            xorInto(m, n - bs, k2);
        }
        return lastBlock(encryptCbc(iv, m));
    }

    static byte[] shiftLeft(byte[] in, int rb) {
        byte[] out = new byte[in.length];
        int carry = 0;
        for (int i = in.length - 1; i >= 0; i--) {
            int v = in[i] & 0xFF;
            out[i] = (byte) ((v << 1) | carry);
            carry = (v >> 7) & 1;
        }
        if ((in[0] & 0x80) != 0) out[in.length - 1] ^= (byte) rb;
        return out;
    }

    static void xorInto(byte[] buf, int off, byte[] k) {
        for (int i = 0; i < k.length; i++) buf[off + i] ^= k[i];
    }
}
