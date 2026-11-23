package nz.cardforge.desfire;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Card-side emulation of a single DESFire EV1 application holding the credential file, for Android HCE
 * (phone acts as the card). Read-only: the only key it knows is the read key (key 1).
 *
 * Accepts ISO 7816 SELECT (routes the HCE session), ISO-wrapped native commands (CLA 90) and
 * unwrapped native frames. Supported: GetVersion, SelectApplication, GetApplicationIDs, AuthenticateAES (key 1),
 * GetKeySettings, GetFileIDs, GetFileSettings, ReadData, GetCardUID, additional frames.
 */
public final class DesfireEmulator {

    private static final class Err extends Exception {
        final int code;
        Err(int code) { this.code = code; }
    }

    private static final class Resp {
        final int status;
        final byte[] data;
        Resp(int status, byte[] data) { this.status = status; this.data = data; }
    }

    private static final byte[] SW_OK = {(byte) 0x90, 0x00};
    private static final byte[] SW_INS_NOT_SUPPORTED = {0x6D, 0x00};

    private final int aid, fileNo, accessRights;
    private final DesfireSession.Comm comm;
    private final byte[] readKey, file, uid;
    private final SecureRandom rnd = new SecureRandom();

    private int selected = 0; // 0 = PICC level
    private KeyCipher session;
    private byte[] iv;
    private int authKey = -1;
    private KeyCipher pendCipher;
    private byte[] pendRndB, pendEk;
    private int pendKey;
    private byte[][] frames;
    private int frameIdx;

    public DesfireEmulator(CardProfile p, byte[] fileContent, byte[] uid7) {
        this.aid = p.aid;
        this.fileNo = p.fileNo;
        this.comm = p.comm;
        this.accessRights = CardProfile.ACCESS_RIGHTS;
        this.readKey = p.readKey.clone();
        this.file = fileContent.clone();
        this.uid = uid7.clone();
    }

    /**
     * Builds the credential file content for a phone credential.
     * With the data layer on: IV(16) || AES-256-CBC(dataKey, IV, credential block) as in ICT's
     * "AES 256 Decrypt CBC" + "AES IV in first block" card linkage flags.
     */
    public static byte[] mobileFile(CardProfile p, Credential c, boolean dataLayer, SecureRandom rnd) {
        if (!dataLayer) return c.toFile(p.fileSize);
        try {
            byte[] ivb = new byte[16];
            rnd.nextBytes(ivb);
            Cipher ci = Cipher.getInstance("AES/CBC/NoPadding");
            ci.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(p.mobileDataKey, "AES"), new IvParameterSpec(ivb));
            byte[] ct = ci.doFinal(c.toFile(16));
            return Arrays.copyOf(Hex.concat(ivb, ct), Math.max(32, p.fileSize));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private void resetAuth() {
        session = null;
        iv = null;
        authKey = -1;
        pendCipher = null;
    }

    /** Process one APDU from the reader and return the response APDU. */
    public byte[] process(byte[] apdu) {
        if (apdu == null || apdu.length == 0) return SW_INS_NOT_SUPPORTED;
        int cla = apdu[0] & 0xFF;
        if (cla == 0x00 && apdu.length >= 4 && (apdu[1] & 0xFF) == 0xA4) {
            // ISO SELECT by AID (what routed the HCE session) or by file id: answer OK at PICC level.
            resetAuth();
            frames = null;
            selected = 0;
            return SW_OK;
        }
        boolean wrapped = cla == 0x90 && apdu.length >= 5;
        int cmd;
        byte[] data;
        if (wrapped) {
            cmd = apdu[1] & 0xFF;
            int lc = apdu.length > 5 ? apdu[4] & 0xFF : 0;
            if (5 + lc > apdu.length) return new byte[] {0x67, 0x00};
            data = Arrays.copyOfRange(apdu, 5, 5 + lc);
        } else if (cla != 0x00) {
            cmd = cla; // native (unwrapped) DESFire frame
            data = Arrays.copyOfRange(apdu, 1, apdu.length);
        } else {
            return SW_INS_NOT_SUPPORTED; // other ISO 7816 commands (READ BINARY etc.) aren't emulated
        }
        Resp r;
        try {
            r = handle(cmd, data);
        } catch (Err e) {
            resetAuth();
            frames = null;
            r = new Resp(e.code, new byte[0]);
        }
        return wrapped
                ? Hex.concat(r.data, new byte[] {(byte) 0x91, (byte) r.status})
                : Hex.concat(new byte[] {(byte) r.status}, r.data);
    }

    private void inMac(int cmd, byte[] d) {
        if (session != null) iv = session.cmac(iv, Hex.concat(new byte[] {(byte) cmd}, d));
    }

    private Resp out(byte[] data) {
        if (session == null) return new Resp(0, data);
        byte[] mac = session.cmac(iv, Hex.concat(data, new byte[] {0}));
        iv = mac;
        return new Resp(0, Hex.concat(data, Arrays.copyOf(mac, 8)));
    }

    private Resp outEnc(byte[] data) {
        byte[] ct = session.encryptCbc(iv, Hex.zeroPad(Hex.concat(data, Crc32Desfire.compute(data, new byte[] {0})), session.blockSize()));
        iv = session.lastBlock(ct);
        return new Resp(0, ct);
    }

    private void requireApp() throws Err {
        if (selected != aid) throw new Err(0x1C);
    }

    private Resp handle(int cmd, byte[] d) throws Err {
        if (cmd != 0xAF) frames = null;
        switch (cmd) {
            case 0xAF: {
                if (pendCipher != null) return finishAuth(d);
                if (frames != null) {
                    byte[] f = frames[frameIdx++];
                    boolean last = frameIdx == frames.length;
                    if (last) frames = null;
                    return new Resp(last ? 0x00 : 0xAF, f);
                }
                throw new Err(0x1C);
            }
            case 0x60: { // GetVersion: report a DESFire EV1 4K
                inMac(cmd, d);
                byte[] f1 = Hex.decode("04010101001805"), f2 = Hex.decode("04010101001805");
                byte[] f3 = Hex.concat(uid, Hex.decode("CF0000000000"), new byte[] {0x26, 0x20});
                if (session != null) {
                    byte[] mac = session.cmac(iv, Hex.concat(f1, f2, f3, new byte[] {0}));
                    iv = mac;
                    f3 = Hex.concat(f3, Arrays.copyOf(mac, 8));
                }
                frames = new byte[][] {f2, f3};
                frameIdx = 0;
                return new Resp(0xAF, f1);
            }
            case 0x5A: {
                resetAuth();
                if (d.length < 3) throw new Err(0x7E);
                int a = Hex.fromLe24(d, 0);
                if (a != 0 && a != aid) throw new Err(0xA0);
                selected = a;
                return new Resp(0, new byte[0]);
            }
            case 0x6A: {
                if (selected != 0) throw new Err(0x1C);
                inMac(cmd, d);
                return out(Hex.le24(aid));
            }
            case 0x45: {
                inMac(cmd, d);
                return out(selected == 0 ? new byte[] {0x0B, 0x01} : new byte[] {(byte) CardProfile.APP_KEY_SETTINGS, (byte) (0x80 | CardProfile.APP_KEY_COUNT)});
            }
            case 0x6F: {
                requireApp();
                inMac(cmd, d);
                return out(new byte[] {(byte) fileNo});
            }
            case 0xF5: {
                requireApp();
                if (d.length < 1 || d[0] != fileNo) throw new Err(0xF0);
                inMac(cmd, d);
                return out(Hex.concat(new byte[] {0x00, (byte) comm.code, (byte) accessRights, (byte) (accessRights >> 8)}, Hex.le24(file.length)));
            }
            case 0xAA: {
                resetAuth();
                if (d.length < 1) throw new Err(0x7E);
                int keyNo = d[0] & 0xFF;
                if (selected != aid || keyNo != CardProfile.KEY_READ) throw new Err(0xAE); // only the read key exists here
                pendCipher = KeyCipher.aes(readKey);
                pendRndB = new byte[16];
                rnd.nextBytes(pendRndB);
                pendEk = pendCipher.encryptCbc(new byte[16], pendRndB);
                pendKey = keyNo;
                return new Resp(0xAF, pendEk);
            }
            case 0x0A:
            case 0x1A:
            case 0x71:
                throw new Err(0xAE); // legacy/ISO/EV2 auth not offered: read key is AES via 0xAA
            case 0xBD: {
                requireApp();
                if (d.length < 7) throw new Err(0x7E);
                if (d[0] != fileNo) throw new Err(0xF0);
                int r = (accessRights >> 12) & 0xF, rw = (accessRights >> 4) & 0xF;
                if (authKey != r && authKey != rw) throw new Err(0x9D);
                int off = Hex.fromLe24(d, 1), len = Hex.fromLe24(d, 4);
                if (len == 0) len = file.length - off;
                if (off < 0 || off + len > file.length) throw new Err(0xBE);
                inMac(cmd, d);
                byte[] data = Arrays.copyOfRange(file, off, off + len);
                return comm == DesfireSession.Comm.ENC ? outEnc(data) : out(data);
            }
            case 0x51: { // GetCardUID (encrypted)
                if (session == null) throw new Err(0xAE);
                inMac(cmd, d);
                return outEnc(uid);
            }
            default:
                throw new Err(0x1C);
        }
    }

    private Resp finishAuth(byte[] token) throws Err {
        KeyCipher c = pendCipher;
        pendCipher = null;
        if (token.length != 32) throw new Err(0x7E);
        byte[] p = c.decryptCbc(c.lastBlock(pendEk), token);
        byte[] rndA = Arrays.copyOf(p, 16);
        if (!Arrays.equals(Arrays.copyOfRange(p, 16, 32), Hex.rotateLeft(pendRndB))) throw new Err(0xAE);
        byte[] resp = c.encryptCbc(c.lastBlock(token), Hex.rotateLeft(rndA));
        session = KeyCipher.aes(Hex.concat(Hex.slice(rndA, 0, 4), Hex.slice(pendRndB, 0, 4), Hex.slice(rndA, 12, 16), Hex.slice(pendRndB, 12, 16)));
        iv = new byte[16];
        authKey = pendKey;
        return new Resp(0, resp);
    }
}
