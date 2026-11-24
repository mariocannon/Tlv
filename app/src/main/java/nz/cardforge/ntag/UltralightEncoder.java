package nz.cardforge.ntag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.DesfireSession;

/**
 * TEST-ONLY Verity tags on MIFARE Ultralight, Ultralight EV1 and Ultralight C.
 *
 * These chips can't mirror a counter into the URL, so they get a short static link
 * (…/t/?s=<code>). Tapping shows the product page, but a copied link looks identical,
 * so they're flagged as test tags everywhere.
 */
public final class UltralightEncoder {

    public static final class Model {
        public final String name;
        public final int userBytes, ccSize;
        public Model(String name, int userBytes, int ccSize) { this.name = name; this.userBytes = userBytes; this.ccSize = ccSize; }
    }

    public static final Model ULTRALIGHT = new Model("MIFARE Ultralight", 48, 0x06);
    public static final Model ULTRALIGHT_C = new Model("MIFARE Ultralight C", 144, 0x12);
    public static final Model UL_EV1_48 = new Model("MIFARE Ultralight EV1 (MF0UL11)", 48, 0x06);
    public static final Model UL_EV1_128 = new Model("MIFARE Ultralight EV1 (MF0UL21)", 128, 0x10);

    private static final int FIRST_USER_PAGE = 4;
    private final DesfireSession.Transceiver io;

    public UltralightEncoder(DesfireSession.Transceiver io) { this.io = io; }

    /** Generic model from the capability container size byte (CC[2] x 8 = data bytes), for compatible/clone chips. */
    public static Model fromCc(int ccSize) {
        return new Model("Ultralight-compatible (" + ccSize * 8 + " bytes)", Math.min(ccSize * 8, 4 * 60), ccSize);
    }

    /** Model from a GET_VERSION reply (Ultralight EV1 answers it; older Ultralights don't). */
    public static Model fromVersion(byte[] v) throws DesfireException {
        if (v == null || v.length < 8 || v[1] != 0x04 || v[2] != 0x03) throw new DesfireException("Not a MIFARE Ultralight");
        switch (v[6] & 0xFF) {
            case 0x0B: return UL_EV1_48;
            case 0x0E: return UL_EV1_128;
            default: return UL_EV1_48; // unknown size: assume the smallest
        }
    }

    /** NDEF TLV for a URL. The FE terminator is dropped if the message exactly fills the memory. */
    static byte[] ndef(String url, int capacity) throws DesfireException {
        byte[] t = Ntag21xEncoder.ndefTlv(url);
        if (t.length <= capacity) return t;
        if (t.length - 1 == capacity) { byte[] s = new byte[capacity]; System.arraycopy(t, 0, s, 0, capacity); return s; }
        throw new DesfireException("Link is " + (t.length - capacity) + " bytes too long for this tag");
    }

    public void encode(Model m, String url) throws IOException, DesfireException {
        byte[] data = ndef(url, m.userBytes);
        byte[] cc = read(3);
        if (cc[0] != (byte) 0xE1) {
            if (cc[0] == 0 && cc[1] == 0 && cc[2] == 0 && cc[3] == 0) writePage(3, new byte[] { (byte) 0xE1, 0x10, (byte) m.ccSize, 0x00 });
            else throw new DesfireException("Tag isn't NDEF formatted");
        } else if ((cc[3] & 0xF0) != 0) throw new DesfireException("This tag is set to read-only");
        for (int off = 0; off < data.length; off += 4) {
            byte[] d = new byte[4];
            System.arraycopy(data, off, d, 0, Math.min(4, data.length - off));
            writePage(FIRST_USER_PAGE + off / 4, d);
        }
    }

    public void reset() throws IOException, DesfireException {
        writePage(FIRST_USER_PAGE, new byte[] { 0x03, 0x00, (byte) 0xFE, 0x00 });
    }

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

    private byte[] read(int page) throws IOException, DesfireException {
        byte[] r = io.transceive(new byte[] { 0x30, (byte) page });
        if (r == null || r.length < 16) throw new DesfireException("Read failed at page " + page);
        return r;
    }

    private void writePage(int page, byte[] d) throws IOException, DesfireException {
        byte[] r = io.transceive(new byte[] { (byte) 0xA2, (byte) page, d[0], d[1], d[2], d[3] });
        if (r == null || r.length < 1 || (r[0] & 0x0F) != 0x0A)
            throw new DesfireException("Write refused at page " + page + " (tag may be locked or password protected)");
    }
}
