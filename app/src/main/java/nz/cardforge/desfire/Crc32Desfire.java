package nz.cardforge.desfire;

/** DESFire EV1+ CRC32: IEEE 802.3 polynomial, init 0xFFFFFFFF, NO final XOR, little-endian output. */
public final class Crc32Desfire {
    private Crc32Desfire() {}

    public static byte[] compute(byte[]... parts) {
        int crc = 0xFFFFFFFF;
        for (byte[] p : parts) {
            for (byte value : p) {
                crc ^= value & 0xFF;
                for (int k = 0; k < 8; k++) {
                    crc = (crc & 1) != 0 ? (crc >>> 1) ^ 0xEDB88320 : crc >>> 1;
                }
            }
        }
        return new byte[] {(byte) crc, (byte) (crc >>> 8), (byte) (crc >>> 16), (byte) (crc >>> 24)};
    }
}
