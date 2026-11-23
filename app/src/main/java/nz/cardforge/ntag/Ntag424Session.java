package nz.cardforge.ntag;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import nz.cardforge.desfire.Crc32Desfire;
import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.DesfireSession;
import nz.cardforge.desfire.Hex;
import nz.cardforge.desfire.KeyCipher;

/**
 * NXP NTAG 424 DNA commands with EV2 secure messaging (AuthenticateEV2First, CommMode.Full).
 * References: NT4H2421Gx datasheet, AN12196 (worked examples used in the unit tests).
 */
public final class Ntag424Session {

    public static final byte[] NDEF_APP_DF_NAME = Hex.decode("D2760000850101");
    public static final int NDEF_FILE_ID = 0xE104;
    public static final int NDEF_FILE_NO = 0x02;

    static final int CMD_AUTH_EV2_FIRST = 0x71, CMD_MORE = 0xAF, CMD_CHANGE_KEY = 0xC4,
            CMD_CHANGE_FILE_SETTINGS = 0x5F, CMD_GET_FILE_SETTINGS = 0xF5;

    private final DesfireSession.Transceiver io;
    private final SecureRandom random;

    // EV2 session state
    private KeyCipher sesEnc, sesMac;
    private byte[] ti;
    private int cmdCtr;
    private int authKeyNo = -1;

    public Ntag424Session(DesfireSession.Transceiver io) { this(io, new SecureRandom()); }

    public Ntag424Session(DesfireSession.Transceiver io, SecureRandom random) {
        this.io = io;
        this.random = random;
    }

    public boolean isAuthenticated() { return sesEnc != null; }

    private void reset() {
        sesEnc = null;
        sesMac = null;
        ti = null;
        cmdCtr = 0;
        authKeyNo = -1;
    }

    // ---------------------------------------------------------------- ISO 7816 commands

    private byte[] iso(byte[] apdu, String what) throws IOException, DesfireException {
        byte[] r = io.transceive(apdu);
        if (r == null || r.length < 2) throw new DesfireException(what + ": no response");
        int sw = ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
        if (sw != 0x9000) throw new DesfireException(String.format("%s failed (SW %04X)", what, sw));
        return Arrays.copyOf(r, r.length - 2);
    }

    /** ISO SELECT of the NDEF application by DF name. Ends any EV2 session. */
    public void selectNdefApplication() throws IOException, DesfireException {
        reset();
        iso(Hex.concat(new byte[] {0x00, (byte) 0xA4, 0x04, 0x0C, 0x07}, NDEF_APP_DF_NAME, new byte[] {0x00}), "Select NDEF application");
    }

    public void selectFile(int fileId) throws IOException, DesfireException {
        iso(new byte[] {0x00, (byte) 0xA4, 0x00, 0x0C, 0x02, (byte) (fileId >> 8), (byte) fileId, 0x00}, "Select file");
    }

    /** ISO UPDATE BINARY in plain mode (file must allow free write, or be in a plain session). */
    public void updateBinary(int offset, byte[] data) throws IOException, DesfireException {
        int pos = 0;
        while (pos < data.length) {
            int n = Math.min(data.length - pos, 128);
            int off = offset + pos;
            iso(Hex.concat(new byte[] {0x00, (byte) 0xD6, (byte) (off >> 8), (byte) off, (byte) n}, Hex.slice(data, pos, pos + n)),
                    "Write NDEF");
            pos += n;
        }
    }

    /** ISO READ BINARY. length 0 = up to 256 bytes. */
    public byte[] readBinary(int offset, int length) throws IOException, DesfireException {
        return iso(new byte[] {0x00, (byte) 0xB0, (byte) (offset >> 8), (byte) offset, (byte) length}, "Read NDEF");
    }

    // ---------------------------------------------------------------- native framing

    private static final class Resp {
        final int status;
        final byte[] data;
        Resp(int status, byte[] data) { this.status = status; this.data = data; }
    }

    private Resp nativeCmd(int cmd, byte[] data) throws IOException, DesfireException {
        byte[] apdu = data.length == 0
                ? new byte[] {(byte) 0x90, (byte) cmd, 0, 0, 0}
                : Hex.concat(new byte[] {(byte) 0x90, (byte) cmd, 0, 0, (byte) data.length}, data, new byte[] {0});
        byte[] r = io.transceive(apdu);
        if (r == null || r.length < 2) throw new DesfireException("Tag returned no response");
        int sw1 = r[r.length - 2] & 0xFF, sw2 = r[r.length - 1] & 0xFF;
        if (sw1 != 0x91) throw new DesfireException(String.format("Unexpected response (SW %02X%02X)", sw1, sw2));
        return new Resp(sw2, Arrays.copyOf(r, r.length - 2));
    }

    // ---------------------------------------------------------------- EV2 authentication

    /** AuthenticateEV2First with an AES-128 key. */
    public void authenticateEv2First(int keyNo, byte[] key) throws IOException, DesfireException {
        reset();
        KeyCipher k = KeyCipher.aes(key);
        byte[] zero = new byte[16];
        Resp r1 = nativeCmd(CMD_AUTH_EV2_FIRST, new byte[] {(byte) keyNo, 0x00});
        if (r1.status != 0xAF || r1.data.length != 16) throw new DesfireException(r1.status, "Authenticate key " + keyNo);
        byte[] rndB = k.decryptCbc(zero, r1.data);
        byte[] rndA = new byte[16];
        random.nextBytes(rndA);
        Resp r2 = nativeCmd(CMD_MORE, k.encryptCbc(zero, Hex.concat(rndA, Hex.rotateLeft(rndB))));
        if (r2.status != 0x00) throw new DesfireException(r2.status, "Authenticate key " + keyNo);
        if (r2.data.length != 32) throw new DesfireException("Unexpected authentication response length " + r2.data.length);
        byte[] plain = k.decryptCbc(zero, r2.data);
        if (!Arrays.equals(Hex.slice(plain, 4, 20), Hex.rotateLeft(rndA))) throw new DesfireException("Tag failed mutual authentication");
        ti = Hex.slice(plain, 0, 4);
        byte[][] keys = sessionKeys(key, rndA, rndB);
        sesEnc = KeyCipher.aes(keys[0]);
        sesMac = KeyCipher.aes(keys[1]);
        cmdCtr = 0;
        authKeyNo = keyNo;
    }

    /** SesAuthENCKey and SesAuthMACKey from RndA/RndB (NT4H2421Gx section 9.1.7). */
    static byte[][] sessionKeys(byte[] key, byte[] rndA, byte[] rndB) {
        byte[] mid = Hex.xor(Hex.slice(rndA, 2, 8), Hex.slice(rndB, 0, 6));
        byte[] ctx = Hex.concat(Hex.slice(rndA, 0, 2), mid, Hex.slice(rndB, 6, 16), Hex.slice(rndA, 8, 16));
        KeyCipher k = KeyCipher.aes(key);
        byte[] enc = k.cmac(new byte[16], Hex.concat(Hex.decode("A55A00010080"), ctx));
        byte[] mac = k.cmac(new byte[16], Hex.concat(Hex.decode("5AA500010080"), ctx));
        return new byte[][] {enc, mac};
    }

    // ---------------------------------------------------------------- secure messaging

    static byte[] truncateMac(byte[] full) {
        byte[] t = new byte[8];
        for (int i = 0; i < 8; i++) t[i] = full[i * 2 + 1];
        return t;
    }

    private byte[] ctrLe() { return new byte[] {(byte) cmdCtr, (byte) (cmdCtr >> 8)}; }

    static byte[] padIso(byte[] data) {
        int n = (data.length / 16 + 1) * 16;
        byte[] out = Arrays.copyOf(data, n);
        out[data.length] = (byte) 0x80;
        return out;
    }

    /** Sends a command in CommMode.Full. Returns response data (without MAC). */
    private byte[] fullCommand(int cmd, byte[] header, byte[] data, boolean expectResponseMac, String what)
            throws IOException, DesfireException {
        if (sesEnc == null) throw new DesfireException(what + " needs authentication first");
        byte[] ivc = sesEnc.encryptCbc(new byte[16], Hex.concat(new byte[] {(byte) 0xA5, 0x5A}, ti, ctrLe(), new byte[8]));
        byte[] enc = data.length == 0 ? new byte[0] : sesEnc.encryptCbc(ivc, padIso(data));
        byte[] mac = truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {(byte) cmd}, ctrLe(), ti, header, enc)));
        Resp r = nativeCmd(cmd, Hex.concat(header, enc, mac));
        if (r.status != 0x00) {
            reset();
            throw new DesfireException(r.status, what);
        }
        cmdCtr++;
        if (!expectResponseMac) return r.data;
        if (r.data.length < 8) {
            reset();
            throw new DesfireException(what + ": response MAC missing");
        }
        byte[] body = Arrays.copyOf(r.data, r.data.length - 8);
        byte[] got = Hex.slice(r.data, r.data.length - 8, r.data.length);
        byte[] want = truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {0x00}, ctrLe(), ti, body)));
        if (!Arrays.equals(got, want)) {
            reset();
            throw new DesfireException(what + ": response MAC mismatch");
        }
        return body;
    }

    /** ChangeFileSettings (0x5F) in CommMode.Full. */
    public void changeFileSettings(int fileNo, byte[] settings) throws IOException, DesfireException {
        fullCommand(CMD_CHANGE_FILE_SETTINGS, new byte[] {(byte) fileNo}, settings, true, "ChangeFileSettings");
    }

    /**
     * ChangeKey (0xC4) in CommMode.Full.
     * @param oldKey current value of the key being changed (ignored when it is the authenticated key).
     */
    public void changeKey(int keyNo, byte[] newKey, byte[] oldKey, int keyVersion) throws IOException, DesfireException {
        boolean authKey = keyNo == authKeyNo;
        byte[] data = authKey
                ? Hex.concat(newKey, new byte[] {(byte) keyVersion})
                : Hex.concat(Hex.xor(newKey, oldKey), new byte[] {(byte) keyVersion}, Crc32Desfire.compute(newKey));
        fullCommand(CMD_CHANGE_KEY, new byte[] {(byte) keyNo}, data, !authKey, "ChangeKey " + keyNo);
        if (authKey) reset(); // the tag ends the session after its own key changes
    }

    /** GetFileSettings (0xF5) in CommMode.MAC. */
    public byte[] getFileSettings(int fileNo) throws IOException, DesfireException {
        if (sesMac == null) throw new DesfireException("GetFileSettings needs authentication first");
        byte[] header = {(byte) fileNo};
        byte[] mac = truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {(byte) CMD_GET_FILE_SETTINGS}, ctrLe(), ti, header)));
        Resp r = nativeCmd(CMD_GET_FILE_SETTINGS, Hex.concat(header, mac));
        if (r.status != 0x00) {
            reset();
            throw new DesfireException(r.status, "GetFileSettings");
        }
        cmdCtr++;
        byte[] body = Arrays.copyOf(r.data, r.data.length - 8);
        byte[] want = truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {0x00}, ctrLe(), ti, body)));
        if (!Arrays.equals(Hex.slice(r.data, r.data.length - 8, r.data.length), want)) {
            reset();
            throw new DesfireException("GetFileSettings: response MAC mismatch");
        }
        return body;
    }
}
