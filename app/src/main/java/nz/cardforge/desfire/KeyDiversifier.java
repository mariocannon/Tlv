package nz.cardforge.desfire;

import java.util.Arrays;

/**
 * NXP AN10922 AES-128 key diversification.
 * divKey = CMAC(K, 0x01 || UID || AID(LSB first) || SystemIdentifier), padded to 32 bytes.
 * Supported by most configurable readers as "NXP AN10922 / AV2 AES-128 diversification".
 */
public final class KeyDiversifier {
    private KeyDiversifier() {}

    public static byte[] input(byte[] uid, int aid, byte[] systemId) {
        return Hex.concat(uid, Hex.le24(aid), systemId == null ? new byte[0] : systemId);
    }

    public static byte[] aes128(byte[] masterKey, byte[] divInput) {
        if (divInput.length < 1 || divInput.length > 31) throw new IllegalArgumentException("Diversification input must be 1..31 bytes");
        KeyCipher c = KeyCipher.aes(masterKey);
        byte[] l = c.encryptCbc(new byte[16], new byte[16]);
        byte[] k1 = KeyCipher.shiftLeft(l, 0x87);
        byte[] k2 = KeyCipher.shiftLeft(k1, 0x87);
        byte[] m = Hex.concat(new byte[] {0x01}, divInput);
        byte[] block;
        if (m.length == 32) {
            block = m;
            KeyCipher.xorInto(block, 16, k1);
        } else {
            block = Arrays.copyOf(m, 32);
            block[m.length] = (byte) 0x80;
            KeyCipher.xorInto(block, 16, k2);
        }
        return c.lastBlock(c.encryptCbc(new byte[16], block));
    }
}
