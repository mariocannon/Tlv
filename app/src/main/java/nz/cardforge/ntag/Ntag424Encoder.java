package nz.cardforge.ntag;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.Hex;

/**
 * Turns a factory NTAG 424 DNA into a Verity tag, reads its tap URL back, and wipes it again.
 *
 * Key slots: K0 app master (per tag), K1 SDM meta-read (PICCData encryption, shared per brand),
 * K2 SDM file-read (MAC, per tag), K3/K4 unused and locked (per tag).
 * The NDEF file is set to: read free, write/change with K0, SUN with encrypted PICCData + MAC.
 */
public final class Ntag424Encoder {

    /** The five keys for one tag (16 bytes each). */
    public static final class TagKeys {
        public final byte[][] k = new byte[5][];
        public TagKeys(byte[] k0, byte[] k1, byte[] k2, byte[] k3, byte[] k4) {
            k[0] = k0; k[1] = k1; k[2] = k2; k[3] = k3; k[4] = k4;
            for (byte[] x : k) if (x == null || x.length != 16) throw new IllegalArgumentException("Each key must be 16 bytes");
        }
        public static TagKeys factory() {
            return new TagKeys(new byte[16], new byte[16], new byte[16], new byte[16], new byte[16]);
        }
    }

    /** Where the tag mirrors its dynamic data inside the NDEF file. */
    public static final class Layout {
        public final byte[] file;
        public final int piccOffset, macOffset;
        Layout(byte[] file, int piccOffset, int macOffset) {
            this.file = file; this.piccOffset = piccOffset; this.macOffset = macOffset;
        }
    }

    private static final int URI_HTTPS = 0x04;
    private static final int KEY_VERSION = 0x01;

    private final Ntag424Session s;

    public Ntag424Encoder(Ntag424Session session) { this.s = session; }

    /**
     * Builds the NDEF file (NLEN + one URI record) for a URL template that contains
     * "p=" followed by 32 placeholder characters and "m=" followed by 16.
     */
    public static Layout layout(String urlTemplate) {
        if (!urlTemplate.startsWith("https://")) throw new IllegalArgumentException("URL must start with https://");
        String rest = urlTemplate.substring("https://".length());
        byte[] uri = rest.getBytes(StandardCharsets.US_ASCII);
        int payloadLen = 1 + uri.length;
        if (payloadLen > 250) throw new IllegalArgumentException("URL too long");
        byte[] record = Hex.concat(new byte[] {(byte) 0xD1, 0x01, (byte) payloadLen, 0x55, (byte) URI_HTTPS}, uri);
        byte[] file = Hex.concat(new byte[] {(byte) (record.length >> 8), (byte) record.length}, record);
        String asText = new String(file, StandardCharsets.ISO_8859_1);
        int p = asText.indexOf("&p=") + 3, m = asText.indexOf("&m=", p) + 3;
        if (p < 3 || m < 3 || m - p < 35) throw new IllegalArgumentException("URL template needs &p= and &m= placeholders");
        return new Layout(file, p, m);
    }

    /** SDM file settings: plain file, SUN on, UID + counter mirrored inside encrypted PICCData, ASCII. */
    public static byte[] sdmSettings(Layout l) {
        return Hex.concat(
                new byte[] {0x40},              // FileOption: SDM enabled, CommMode plain
                new byte[] {0x00, (byte) 0xE0}, // AccessRights: RW=K0 Change=K0 | Read=free Write=K0
                new byte[] {(byte) 0xC1},       // SDMOptions: UID mirror, SDMReadCtr mirror, ASCII
                new byte[] {(byte) 0xF1, 0x12}, // SDMAccessRights: RFU=F CtrRet=K1 | MetaRead=K1 FileRead=K2
                Hex.le24(l.piccOffset),         // PICCDataOffset
                Hex.le24(l.macOffset),          // SDMMACInputOffset (= MAC offset, so MAC input is empty)
                Hex.le24(l.macOffset));         // SDMMACOffset
    }

    /** Factory file settings for the NDEF file. */
    public static byte[] factorySettings() {
        return new byte[] {0x00, (byte) 0xE0, (byte) 0xEE};
    }

    /** Encodes a factory-fresh tag. Keys must not be the factory keys. */
    public void encode(TagKeys keys, String urlTemplate) throws IOException, DesfireException {
        Layout l = layout(urlTemplate);
        byte[] zero = new byte[16];
        s.selectNdefApplication();
        s.selectFile(Ntag424Session.NDEF_FILE_ID);
        s.updateBinary(0, l.file);
        s.authenticateEv2First(0, zero);
        s.changeFileSettings(Ntag424Session.NDEF_FILE_NO, sdmSettings(l));
        for (int n = 1; n <= 4; n++) s.changeKey(n, keys.k[n], zero, KEY_VERSION);
        s.changeKey(0, keys.k[0], null, KEY_VERSION);
    }

    /** Returns an encoded tag to factory state (all keys zero, plain NDEF file, empty message). */
    public void reset(TagKeys current) throws IOException, DesfireException {
        byte[] zero = new byte[16];
        s.selectNdefApplication();
        s.authenticateEv2First(0, current.k[0]);
        s.changeFileSettings(Ntag424Session.NDEF_FILE_NO, factorySettings());
        for (int n = 1; n <= 4; n++) s.changeKey(n, zero, current.k[n], 0x00);
        s.changeKey(0, zero, null, 0x00);
        s.selectNdefApplication();
        s.selectFile(Ntag424Session.NDEF_FILE_ID);
        s.updateBinary(0, new byte[] {0x00, 0x00});
    }

    /** Reads the NDEF file the way a phone would and returns the https URL (with live p= and m=). */
    public String readUrl() throws IOException, DesfireException {
        s.selectNdefApplication();
        s.selectFile(Ntag424Session.NDEF_FILE_ID);
        byte[] f = s.readBinary(0, 0);
        if (f.length < 7) throw new DesfireException("Tag has no NDEF message");
        int nlen = ((f[0] & 0xFF) << 8) | (f[1] & 0xFF);
        if (nlen < 5 || 2 + nlen > f.length) throw new DesfireException("Tag has no NDEF message");
        if ((f[2] & 0xFF) != 0xD1 || f[3] != 0x01 || f[5] != 0x55) throw new DesfireException("NDEF record is not a URL");
        int payloadLen = f[4] & 0xFF;
        int prefix = f[6] & 0xFF;
        String head = prefix == 0x04 ? "https://" : prefix == 0x03 ? "http://" : "";
        return head + new String(f, 7, payloadLen - 1, StandardCharsets.US_ASCII);
    }

    /** True if the tag still has its factory app master key (i.e. is blank). */
    public boolean isFactory() throws IOException {
        try {
            s.selectNdefApplication();
            s.authenticateEv2First(0, new byte[16]);
            return true;
        } catch (DesfireException e) {
            return false;
        }
    }
}
