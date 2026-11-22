package nz.cardforge.desfire;

import java.util.Arrays;

/**
 * Site code + card ID credential stored in the DESFire standard data file.
 *
 *   offset 0 : site code then card ID, big-endian   <- ICT reader reads bits from the start of the file
 *   then     : 'C' 'F' <format id>                  <- marker so the app can recognise its own cards
 *   then     : 00 padding to file size
 *
 * The ICT custom card format string (e.g. %16s%16c) consumes the leading bits; the marker is ignored by the reader.
 */
public final class Credential {
    public static final byte M1 = 'C', M2 = 'F';

    public enum Format {
        W26(2, 1, 2, "26-bit style: 8-bit site, 16-bit card"),
        W34(3, 2, 2, "34-bit style: 16-bit site, 16-bit card"),
        RAW48(1, 2, 4, "48-bit: 16-bit site, 32-bit card");

        public final int id, siteBytes, cardBytes;
        public final String label;

        Format(int id, int siteBytes, int cardBytes, String label) {
            this.id = id;
            this.siteBytes = siteBytes;
            this.cardBytes = cardBytes;
            this.label = label;
        }

        public int length() { return siteBytes + cardBytes; }
        public long maxSite() { return (1L << (siteBytes * 8)) - 1; }
        public long maxCard() { return (1L << (cardBytes * 8)) - 1; }

        /** ICT custom card format string, e.g. %16s%16c. */
        public String ictFormatString() { return "%" + (siteBytes * 8) + "s%" + (cardBytes * 8) + "c"; }

        public static Format fromId(int id) {
            for (Format f : values()) if (f.id == id) return f;
            throw new IllegalArgumentException("Unknown format id " + id);
        }
    }

    public final Format format;
    public final long site;
    public final long card;

    public Credential(Format format, long site, long card) {
        if (site < 0 || site > format.maxSite()) throw new IllegalArgumentException("Site code must be 0.." + format.maxSite());
        if (card < 0 || card > format.maxCard()) throw new IllegalArgumentException("Card ID must be 0.." + format.maxCard());
        this.format = format;
        this.site = site;
        this.card = card;
    }

    public byte[] credentialBytes() {
        byte[] out = new byte[format.length()];
        put(out, 0, site, format.siteBytes);
        put(out, format.siteBytes, card, format.cardBytes);
        return out;
    }

    public byte[] toFile(int fileSize) {
        byte[] data = Hex.concat(credentialBytes(), new byte[] {M1, M2, (byte) format.id});
        if (data.length > fileSize) throw new IllegalArgumentException("File too small for credential");
        return Arrays.copyOf(data, fileSize);
    }

    public static Credential parse(byte[] file) throws DesfireException {
        for (Format f : Format.values()) {
            int n = f.length();
            if (file.length >= n + 3 && file[n] == M1 && file[n + 1] == M2 && (file[n + 2] & 0xFF) == f.id) {
                return new Credential(f, get(file, 0, f.siteBytes), get(file, f.siteBytes, f.cardBytes));
            }
        }
        throw new DesfireException("File doesn't contain a CardForge credential");
    }

    private static void put(byte[] b, int off, long v, int n) {
        for (int i = 0; i < n; i++) b[off + i] = (byte) (v >>> (8 * (n - 1 - i)));
    }

    private static long get(byte[] b, int off, int n) {
        long v = 0;
        for (int i = 0; i < n; i++) v = (v << 8) | (b[off + i] & 0xFF);
        return v;
    }

    @Override
    public String toString() {
        return "Site " + site + " / Card " + card + " (" + format.name() + ")";
    }
}
