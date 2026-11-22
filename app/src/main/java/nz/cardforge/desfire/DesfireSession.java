package nz.cardforge.desfire;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * MIFARE DESFire EV1/EV2/EV3 native command set (ISO 7816 wrapped) with EV1 secure messaging
 * (AuthenticateAES 0xAA / AuthenticateISO 0x1A, CMAC + CRC32, CBC with chained IV).
 */
public final class DesfireSession {

    /** Sends one ISO 7816 APDU and returns the raw response (data + SW1 SW2). */
    public interface Transceiver {
        byte[] transceive(byte[] apdu) throws IOException;
    }

    public enum Comm {
        PLAIN(0x00), MAC(0x01), ENC(0x03);
        public final int code;
        Comm(int code) { this.code = code; }
        public static Comm fromCode(int c) {
            for (Comm m : values()) if (m.code == c) return m;
            throw new IllegalArgumentException("Bad comm mode " + c);
        }
    }

    // Native command codes
    static final int CMD_AUTH_ISO = 0x1A, CMD_AUTH_AES = 0xAA, CMD_MORE = 0xAF, CMD_GET_VERSION = 0x60,
            CMD_SELECT_APP = 0x5A, CMD_GET_AIDS = 0x6A, CMD_CREATE_APP = 0xCA, CMD_DELETE_APP = 0xDA,
            CMD_CREATE_STD_FILE = 0xCD, CMD_CHANGE_KEY = 0xC4, CMD_CHANGE_KEY_SETTINGS = 0x54,
            CMD_WRITE_DATA = 0x3D, CMD_READ_DATA = 0xBD, CMD_GET_KEY_SETTINGS = 0x45;

    private final Transceiver io;
    private final SecureRandom random;
    private KeyCipher session;
    private byte[] iv;
    private int authKeyNo = -1;

    public DesfireSession(Transceiver io) { this(io, new SecureRandom()); }

    public DesfireSession(Transceiver io, SecureRandom random) {
        this.io = io;
        this.random = random;
    }

    public boolean isAuthenticated() { return session != null; }

    private void reset() {
        session = null;
        iv = null;
        authKeyNo = -1;
    }

    // ---------------------------------------------------------------- framing

    private static final class Resp {
        final int status;
        final byte[] data;
        Resp(int status, byte[] data) { this.status = status; this.data = data; }
    }

    private Resp raw(int cmd, byte[] data) throws IOException, DesfireException {
        byte[] apdu;
        if (data.length == 0) {
            apdu = new byte[] {(byte) 0x90, (byte) cmd, 0, 0, 0};
        } else {
            apdu = Hex.concat(new byte[] {(byte) 0x90, (byte) cmd, 0, 0, (byte) data.length}, data, new byte[] {0});
        }
        byte[] r = io.transceive(apdu);
        if (r == null || r.length < 2) throw new DesfireException("Card returned no response");
        int sw1 = r[r.length - 2] & 0xFF, sw2 = r[r.length - 1] & 0xFF;
        if (sw1 != 0x91) throw new DesfireException(String.format("Not a DESFire response (SW %02X%02X)", sw1, sw2));
        return new Resp(sw2, Arrays.copyOf(r, r.length - 2));
    }

    /** Sends a command (+ continuation frames) and gathers all response data; throws on error status. */
    private byte[] exchange(int cmd, byte[] data, String what) throws IOException, DesfireException {
        Resp r = raw(cmd, data);
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        acc.write(r.data, 0, r.data.length);
        while (r.status == 0xAF) {
            r = raw(CMD_MORE, new byte[0]);
            acc.write(r.data, 0, r.data.length);
        }
        if (r.status != 0x00) {
            reset();
            throw new DesfireException(r.status, what);
        }
        return acc.toByteArray();
    }

    private int macLen() { return 8; }

    /** Updates the IV with a CMAC over the command (EV1 rule: every command after auth is CMAC'd). */
    private byte[] cmacCommand(byte[] cmdAndData) {
        byte[] mac = session.cmac(iv, cmdAndData);
        iv = mac;
        return mac;
    }

    private byte[] verifyMacResponse(byte[] resp, String what) throws DesfireException {
        if (resp.length < macLen()) {
            reset();
            throw new DesfireException(what + ": response MAC missing");
        }
        byte[] data = Arrays.copyOf(resp, resp.length - macLen());
        byte[] got = Arrays.copyOfRange(resp, resp.length - macLen(), resp.length);
        byte[] mac = session.cmac(iv, Hex.concat(data, new byte[] {0x00}));
        iv = mac;
        if (!Arrays.equals(Arrays.copyOf(mac, macLen()), got)) {
            reset();
            throw new DesfireException(what + ": response MAC mismatch");
        }
        return data;
    }

    /** Plain command; when authenticated, IV is CMAC-chained and response MAC verified. */
    private byte[] plainCommand(int cmd, byte[] data, String what) throws IOException, DesfireException {
        if (session == null) return exchange(cmd, data, what);
        cmacCommand(Hex.concat(new byte[] {(byte) cmd}, data));
        byte[] resp = exchange(cmd, data, what);
        return verifyMacResponse(resp, what);
    }

    /** Encrypts plaintext (already containing any CRC) with the session key, chaining the IV. */
    private byte[] encryptChained(byte[] plain) {
        byte[] ct = session.encryptCbc(iv, Hex.zeroPad(plain, session.blockSize()));
        iv = session.lastBlock(ct);
        return ct;
    }

    private void requireAuth(String what) throws DesfireException {
        if (session == null) throw new DesfireException(what + " requires authentication");
    }

    // ---------------------------------------------------------------- authentication

    public void authenticateAes(int keyNo, byte[] key) throws IOException, DesfireException {
        authenticate(CMD_AUTH_AES, keyNo, KeyCipher.aes(key), 16, key);
    }

    /** ISO authenticate with a 2K3DES key (used for the factory default DES/3DES PICC master key). */
    public void authenticateIso(int keyNo, byte[] key16) throws IOException, DesfireException {
        authenticate(CMD_AUTH_ISO, keyNo, KeyCipher.tdes(key16), 8, key16);
    }

    private void authenticate(int cmd, int keyNo, KeyCipher kc, int rndLen, byte[] key) throws IOException, DesfireException {
        reset();
        Resp r1 = raw(cmd, new byte[] {(byte) keyNo});
        if (r1.status != 0xAF) throw new DesfireException(r1.status, "Authenticate key " + keyNo);
        byte[] ekRndB = r1.data;
        if (ekRndB.length != rndLen) throw new DesfireException("Unexpected challenge length " + ekRndB.length);
        byte[] ivChain = new byte[kc.blockSize()];
        byte[] rndB = kc.decryptCbc(ivChain, ekRndB);
        ivChain = kc.lastBlock(ekRndB);
        byte[] rndA = new byte[rndLen];
        random.nextBytes(rndA);
        byte[] token = kc.encryptCbc(ivChain, Hex.concat(rndA, Hex.rotateLeft(rndB)));
        ivChain = kc.lastBlock(token);
        Resp r2 = raw(CMD_MORE, token);
        if (r2.status != 0x00) throw new DesfireException(r2.status, "Authenticate key " + keyNo);
        if (r2.data.length != rndLen) throw new DesfireException("Unexpected auth response length");
        byte[] rndARot = kc.decryptCbc(ivChain, r2.data);
        if (!Arrays.equals(rndARot, Hex.rotateLeft(rndA))) throw new DesfireException("Card failed mutual authentication");

        byte[] sk;
        if (kc.type() == KeyCipher.Type.AES) {
            sk = Hex.concat(Hex.slice(rndA, 0, 4), Hex.slice(rndB, 0, 4), Hex.slice(rndA, 12, 16), Hex.slice(rndB, 12, 16));
            session = KeyCipher.aes(sk);
        } else {
            boolean singleDes = Arrays.equals(Hex.slice(key, 0, 8), Hex.slice(key, 8, 16));
            byte[] half = Hex.concat(Hex.slice(rndA, 0, 4), Hex.slice(rndB, 0, 4));
            sk = singleDes ? Hex.concat(half, half) : Hex.concat(half, Hex.slice(rndA, 4, 8), Hex.slice(rndB, 4, 8));
            session = KeyCipher.tdes(sk);
        }
        iv = new byte[session.blockSize()];
        authKeyNo = keyNo;
    }

    // ---------------------------------------------------------------- PICC / application commands

    public byte[] getVersion() throws IOException, DesfireException {
        return plainCommand(CMD_GET_VERSION, new byte[0], "GetVersion");
    }

    public void selectApplication(int aid) throws IOException, DesfireException {
        reset();
        exchange(CMD_SELECT_APP, Hex.le24(aid), String.format("Select application %06X", aid));
    }

    public List<Integer> getApplicationIds() throws IOException, DesfireException {
        byte[] d = plainCommand(CMD_GET_AIDS, new byte[0], "GetApplicationIDs");
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i + 3 <= d.length; i += 3) out.add(Hex.fromLe24(d, i));
        return out;
    }

    /** @param keyCountAndType number of keys OR'd with 0x80 for AES keys. */
    public void createApplication(int aid, int keySettings, int keyCountAndType) throws IOException, DesfireException {
        plainCommand(CMD_CREATE_APP, Hex.concat(Hex.le24(aid), new byte[] {(byte) keySettings, (byte) keyCountAndType}),
                String.format("Create application %06X", aid));
    }

    public void deleteApplication(int aid) throws IOException, DesfireException {
        plainCommand(CMD_DELETE_APP, Hex.le24(aid), String.format("Delete application %06X", aid));
    }

    public byte[] getKeySettings() throws IOException, DesfireException {
        return plainCommand(CMD_GET_KEY_SETTINGS, new byte[0], "GetKeySettings");
    }

    /**
     * @param accessRights 16-bit value: Read(15..12) Write(11..8) ReadWrite(7..4) Change(3..0)
     */
    public void createStdDataFile(int fileNo, Comm comm, int accessRights, int size) throws IOException, DesfireException {
        byte[] data = Hex.concat(new byte[] {(byte) fileNo, (byte) comm.code, (byte) accessRights, (byte) (accessRights >> 8)}, Hex.le24(size));
        plainCommand(CMD_CREATE_STD_FILE, data, "Create file " + fileNo);
    }

    /**
     * ChangeKey (EV1 secure messaging).
     * @param keyNoByte key number; at PICC level OR with 0x80 for AES (0x00 = DES/3DES).
     * @param oldKey    current value of the key when it is NOT the key used to authenticate (ignored otherwise).
     * @param aesVersion key version byte appended for AES keys (ignored for DES keys).
     */
    public void changeKey(int keyNoByte, byte[] newKey, byte[] oldKey, int aesVersion, boolean newKeyIsAes)
            throws IOException, DesfireException {
        requireAuth("ChangeKey");
        boolean changingAuthKey = (keyNoByte & 0x0F) == authKeyNo;
        byte[] cmdHdr = new byte[] {(byte) CMD_CHANGE_KEY, (byte) keyNoByte};
        byte[] body = changingAuthKey ? newKey.clone() : Hex.xor(newKey, oldKey);
        if (newKeyIsAes) body = Hex.concat(body, new byte[] {(byte) aesVersion});
        byte[] plain = Hex.concat(body, Crc32Desfire.compute(cmdHdr, body));
        if (!changingAuthKey) plain = Hex.concat(plain, Crc32Desfire.compute(newKey));
        byte[] ct = encryptChained(plain);
        byte[] resp = exchange(CMD_CHANGE_KEY, Hex.concat(new byte[] {(byte) keyNoByte}, ct), "ChangeKey " + (keyNoByte & 0x0F));
        if (changingAuthKey) {
            reset(); // session is invalidated by the card
        } else {
            verifyMacResponse(resp, "ChangeKey");
        }
    }

    public void changeKeySettings(int settings) throws IOException, DesfireException {
        requireAuth("ChangeKeySettings");
        byte[] s = new byte[] {(byte) settings};
        byte[] ct = encryptChained(Hex.concat(s, Crc32Desfire.compute(new byte[] {(byte) CMD_CHANGE_KEY_SETTINGS}, s)));
        byte[] resp = exchange(CMD_CHANGE_KEY_SETTINGS, ct, "ChangeKeySettings");
        verifyMacResponse(resp, "ChangeKeySettings");
    }

    // ---------------------------------------------------------------- data files

    public void writeData(int fileNo, int offset, byte[] data, Comm comm) throws IOException, DesfireException {
        byte[] hdr = Hex.concat(new byte[] {(byte) fileNo}, Hex.le24(offset), Hex.le24(data.length));
        byte[] cmd = new byte[] {(byte) CMD_WRITE_DATA};
        String what = "WriteData file " + fileNo;
        if (session == null) {
            if (comm != Comm.PLAIN) throw new DesfireException(what + " requires authentication");
            exchange(CMD_WRITE_DATA, Hex.concat(hdr, data), what);
            return;
        }
        byte[] payload;
        switch (comm) {
            case ENC:
                payload = Hex.concat(hdr, encryptChained(Hex.concat(data, Crc32Desfire.compute(cmd, hdr, data))));
                break;
            case MAC:
                byte[] mac = cmacCommand(Hex.concat(cmd, hdr, data));
                payload = Hex.concat(hdr, data, Arrays.copyOf(mac, macLen()));
                break;
            default:
                cmacCommand(Hex.concat(cmd, hdr, data));
                payload = Hex.concat(hdr, data);
        }
        byte[] resp = exchange(CMD_WRITE_DATA, payload, what);
        verifyMacResponse(resp, what);
    }

    public byte[] readData(int fileNo, int offset, int length, Comm comm) throws IOException, DesfireException {
        byte[] hdr = Hex.concat(new byte[] {(byte) fileNo}, Hex.le24(offset), Hex.le24(length));
        String what = "ReadData file " + fileNo;
        if (session == null) {
            if (comm != Comm.PLAIN) throw new DesfireException(what + " requires authentication");
            return exchange(CMD_READ_DATA, hdr, what);
        }
        cmacCommand(Hex.concat(new byte[] {(byte) CMD_READ_DATA}, hdr));
        byte[] resp = exchange(CMD_READ_DATA, hdr, what);
        if (comm != Comm.ENC) {
            byte[] d = verifyMacResponse(resp, what);
            if (d.length != length) throw new DesfireException(what + ": unexpected length " + d.length);
            return d;
        }
        if (resp.length == 0 || resp.length % session.blockSize() != 0) {
            reset();
            throw new DesfireException(what + ": bad encrypted length " + resp.length);
        }
        byte[] plain = session.decryptCbc(iv, resp);
        iv = session.lastBlock(resp);
        if (plain.length < length + 4) {
            reset();
            throw new DesfireException(what + ": encrypted response too short");
        }
        byte[] d = Arrays.copyOf(plain, length);
        byte[] crc = Arrays.copyOfRange(plain, length, length + 4);
        if (!Arrays.equals(crc, Crc32Desfire.compute(d, new byte[] {0x00}))) {
            reset();
            throw new DesfireException(what + ": CRC mismatch (wrong key or corrupted data)");
        }
        return d;
    }
}
