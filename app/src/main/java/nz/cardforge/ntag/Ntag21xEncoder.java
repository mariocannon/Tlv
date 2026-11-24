package nz.cardforge.ntag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.DesfireSession;

/**
 * TEST-ONLY Verity tags on cheap NTAG213 / 215 / 216 stickers.
 *
 * These chips have no AES and no signature. We write the tap URL and switch on the chip's
 * "UID + NFC counter mirror", so every phone read fills u= with "<UID hex>x<counter hex>".
 * The server can then check that the counter goes up, but anyone could type a fake link,
 * so these tags are flagged as test tags everywhere. Real products use NTAG 424 DNA.
 *
 * Talks raw NfcA commands (NTAG21x datasheet): GET_VERSION 60, READ 30, WRITE A2.
 */
public final class Ntag21xEncoder {

    /** Which NTAG21x this is and where its config lives. */
    public static final class Model {
        public final String name;
        public final int lastUserPage, cfg0Page, ccSize;
        Model(String name, int lastUserPage, int cfg0Page, int ccSize) {
            this.name = name; this.lastUserPage = lastUserPage; this.cfg0Page = cfg0Page; this.ccSize = ccSize;
        }
        public int userBytes() { return (lastUserPage - 3) * 4; }
    }

    public static final Model NTAG213 = new Model("NTAG213", 0x27, 0x29, 0x12);
    public static final Model NTAG215 = new Model("NTAG215", 0x81, 0x83, 0x3E);
    public static final Model NTAG216 = new Model("NTAG216", 0xE1, 0xE3, 0x6D);

    /** The mirror placeholder: 14 hex UID + 'x' + 6 hex counter. */
    public static final int MIRROR_LEN = 21;
    private static final int FIRST_USER_PAGE = 4;

    private final DesfireSession.Transceiver io;

    public Ntag21xEncoder(DesfireSession.Transceiver io) { this.io = io; }

    /** GET_VERSION: identifies NTAG213/215/216, or throws if it's something else. */
    public Model identify() throws IOException, DesfireException {
        byte[] v = io.transceive(new byte[] { 0x60 });
        // Accept NTAG21x-compatible chips from other makers too (vendor byte != 0x04).
        if (v == null || v.length < 8 || v[2] != 0x04)
            throw new DesfireException("Not an NTAG21x tag (version " + (v == null ? "none" : nz.cardforge.desfire.Hex.encode(v)) + ")");
        switch (v[6] & 0xFF) {
            case 0x0F: return NTAG213;
            case 0x11: return NTAG215;
            case 0x13: return NTAG216;
            default: throw new DesfireException("Unsupported NTAG (size byte " + String.format("%02X", v[6]) + ")");
        }
    }

    /** NDEF TLV for a URL record (short record, 1-byte TLV length). */
    static byte[] ndefTlv(String url) throws DesfireException {
        int prefix; String rest;
        if (url.startsWith("https://")) { prefix = 0x04; rest = url.substring(8); }
        else if (url.startsWith("http://")) { prefix = 0x03; rest = url.substring(7); }
        else { prefix = 0x00; rest = url; }
        byte[] uri = rest.getBytes(StandardCharsets.US_ASCII);
        int plen = uri.length + 1;
        int recLen = 4 + plen;
        if (recLen > 254) throw new DesfireException("URL too long for a test tag");
        byte[] t = new byte[2 + recLen + 1];
        t[0] = 0x03; t[1] = (byte) recLen;
        t[2] = (byte) 0xD1; t[3] = 0x01; t[4] = (byte) plen; t[5] = 0x55; t[6] = (byte) prefix;
        System.arraycopy(uri, 0, t, 7, uri.length);
        t[t.length - 1] = (byte) 0xFE;
        return t;
    }

    /** Byte position (from the start of page 4) where the u= placeholder begins. */
    static int mirrorOffset(String url) throws DesfireException {
        int amp = url.indexOf("&u=");
        int qm = url.indexOf("?u=");
        int at = amp >= 0 ? amp + 3 : qm >= 0 ? qm + 3 : -1;
        if (at < 0) throw new DesfireException("Template has no u= placeholder");
        String head = url.startsWith("https://") ? "https://" : url.startsWith("http://") ? "http://" : "";
        if (url.length() - at < MIRROR_LEN) throw new DesfireException("u= placeholder is too short");
        return 7 + (at - head.length());
    }

    /** Write the URL, then switch on the UID + counter mirror at the u= placeholder and the NFC counter. */
    public Model encode(String template) throws IOException, DesfireException {
        Model m = identify();
        byte[] tlv = ndefTlv(template);
        if (tlv.length > m.userBytes()) throw new DesfireException("URL doesn't fit on " + m.name);

        byte[] cfg = read(m.cfg0Page); // CFG0, CFG1, PWD(masked), PACK(masked)
        if ((cfg[3] & 0xFF) <= m.cfg0Page + 3)
            throw new DesfireException("This tag is password protected (AUTH0=" + (cfg[3] & 0xFF) + "). Use a fresh tag.");
        if ((cfg[4] & 0x40) != 0) throw new DesfireException("This tag's config is locked. Use a fresh tag.");

        ensureCapabilityContainer(m);

        // Mirror off while the NDEF is rewritten, so a half-written tag never mirrors into the wrong place.
        writePage(m.cfg0Page, new byte[] { (byte) (cfg[0] & 0x3F), cfg[1], cfg[2], cfg[3] });
        writeBytes(FIRST_USER_PAGE, tlv);

        int abs = FIRST_USER_PAGE * 4 + mirrorOffset(template);
        int mirrorPage = abs / 4, mirrorByte = abs % 4;
        byte mirror = (byte) (0xC0 | (mirrorByte << 4) | (cfg[0] & 0x04)); // UID+counter, keep STRG_MOD_EN
        writePage(m.cfg0Page, new byte[] { mirror, cfg[1], (byte) mirrorPage, cfg[3] });
        writePage(m.cfg0Page + 1, new byte[] { (byte) (cfg[4] | 0x10), cfg[5], cfg[6], cfg[7] }); // NFC_CNT_EN
        return m;
    }

    /** Clears the URL and turns the mirror off. The chip's counter can't be reset, which is fine. */
    public Model reset() throws IOException, DesfireException {
        Model m = identify();
        byte[] cfg = read(m.cfg0Page);
        writePage(m.cfg0Page, new byte[] { (byte) (cfg[0] & 0x3F), cfg[1], cfg[2], cfg[3] });
        writePage(FIRST_USER_PAGE, new byte[] { 0x03, 0x00, (byte) 0xFE, 0x00 });
        return m;
    }

    /** Reads the URL as a phone would see it (with the mirror filled in). */
    public String readUrl() throws IOException, DesfireException {
        byte[] head = read(FIRST_USER_PAGE);
        if (head[0] != 0x03) throw new DesfireException("Tag has no NDEF message");
        int len = head[1] & 0xFF;
        if (len < 5 || len == 0xFF) throw new DesfireException("Tag has no NDEF message");
        byte[] all = new byte[2 + len];
        for (int off = 0; off < all.length; off += 16) {
            byte[] r = read(FIRST_USER_PAGE + off / 4);
            System.arraycopy(r, 0, all, off, Math.min(16, all.length - off));
        }
        if ((all[2] & 0xFF) != 0xD1 || all[3] != 0x01 || all[5] != 0x55) throw new DesfireException("NDEF record is not a URL");
        int plen = all[4] & 0xFF;
        int prefix = all[6] & 0xFF;
        String p = prefix == 0x04 ? "https://" : prefix == 0x03 ? "http://" : "";
        return p + new String(all, 7, plen - 1, StandardCharsets.US_ASCII);
    }

    // ---------------------------------------------------------------- raw commands

    private void ensureCapabilityContainer(Model m) throws IOException, DesfireException {
        byte[] p = read(3);
        if (p[0] == (byte) 0xE1) return;
        if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0) {
            writePage(3, new byte[] { (byte) 0xE1, 0x10, (byte) m.ccSize, 0x00 }); // one-time write
            return;
        }
        throw new DesfireException("Tag isn't NDEF formatted");
    }

    /** READ: 16 bytes from 4 consecutive pages. */
    byte[] read(int page) throws IOException, DesfireException {
        byte[] r = io.transceive(new byte[] { 0x30, (byte) page });
        if (r == null || r.length < 16) throw new DesfireException("Read failed at page " + page);
        return r;
    }

    void writePage(int page, byte[] d) throws IOException, DesfireException {
        byte[] r = io.transceive(new byte[] { (byte) 0xA2, (byte) page, d[0], d[1], d[2], d[3] });
        if (r == null || r.length < 1 || (r[0] & 0x0F) != 0x0A) throw new DesfireException("Write refused at page " + page);
    }

    private void writeBytes(int startPage, byte[] data) throws IOException, DesfireException {
        for (int off = 0; off < data.length; off += 4) {
            byte[] d = new byte[4];
            System.arraycopy(data, off, d, 0, Math.min(4, data.length - off));
            writePage(startPage + off / 4, d);
        }
    }
}
