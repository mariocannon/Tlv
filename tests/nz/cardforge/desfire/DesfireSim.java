package nz.cardforge.desfire;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Minimal software DESFire EV1 card for testing: PICC + applications, AES/DES keys,
 * standard data files, EV1 secure messaging (CMAC/CRC32/CBC). Card-side logic only.
 */
final class DesfireSim implements DesfireSession.Transceiver {
    static final class Key {
        boolean aes;
        byte[] k = new byte[16];
        int ver;
        Key(boolean aes) { this.aes = aes; }
    }

    static final class FileD {
        int comm, access;
        byte[] data;
    }

    static final class App {
        int settings;
        Key[] keys;
        final Map<Integer, FileD> files = new TreeMap<>();
    }

    static final class Err extends Exception {
        final int code;
        Err(int code) { this.code = code; }
    }

    final byte[] uid = Hex.decode("04112233445566");
    Key piccKey = new Key(false);
    int piccSettings = 0x0F;
    final Map<Integer, App> apps = new LinkedHashMap<>();
    int selected = 0;
    int transactions = 0;

    private final SecureRandom rnd = new SecureRandom();
    private KeyCipher session;
    private byte[] iv;
    private int authKey = -1;

    private KeyCipher pendCipher;
    private byte[] pendRndB, pendEk, pendKeyBytes;
    private int pendKey = -1;

    private byte[][] pendingFrames;
    private int pendingIdx;

    private void resetAuth() {
        session = null;
        iv = null;
        authKey = -1;
        pendCipher = null;
    }

    @Override
    public byte[] transceive(byte[] apdu) {
        transactions++;
        if (apdu[0] != (byte) 0x90) return new byte[] {0x6E, 0x00};
        int cmd = apdu[1] & 0xFF;
        byte[] data = apdu.length > 5 ? Arrays.copyOfRange(apdu, 5, 5 + (apdu[4] & 0xFF)) : new byte[0];
        try {
            return handle(cmd, data);
        } catch (Err e) {
            resetAuth();
            pendingFrames = null;
            return new byte[] {(byte) 0x91, (byte) e.code};
        }
    }

    private static byte[] st(byte[] data, int s) { return Hex.concat(data, new byte[] {(byte) 0x91, (byte) s}); }

    private void inMac(int cmd, byte[] data) {
        if (session != null) iv = session.cmac(iv, Hex.concat(new byte[] {(byte) cmd}, data));
    }

    private byte[] out(byte[] data) {
        if (session == null) return st(data, 0);
        byte[] mac = session.cmac(iv, Hex.concat(data, new byte[] {0}));
        iv = mac;
        return st(Hex.concat(data, Arrays.copyOf(mac, 8)), 0);
    }

    private App app() throws Err {
        if (selected == 0) throw new Err(0x1C);
        return apps.get(selected);
    }

    private Key key(int no) throws Err {
        if (selected == 0) {
            if (no != 0) throw new Err(0x40);
            return piccKey;
        }
        App a = app();
        if (no >= a.keys.length) throw new Err(0x40);
        return a.keys[no];
    }

    private byte[] handle(int cmd, byte[] d) throws Err {
        if (cmd != 0xAF) pendingFrames = null;
        switch (cmd) {
            case 0xAF: {
                if (pendCipher != null) return finishAuth(d);
                if (pendingFrames != null) {
                    byte[] f = pendingFrames[pendingIdx++];
                    boolean last = pendingIdx == pendingFrames.length;
                    if (last) pendingFrames = null;
                    return st(f, last ? 0x00 : 0xAF);
                }
                throw new Err(0x1C);
            }
            case 0x60: {
                inMac(cmd, d);
                byte[] f1 = Hex.decode("04010133001A05"), f2 = Hex.decode("04010103001A05");
                byte[] f3 = Hex.concat(uid, Hex.decode("BA5544332211"), new byte[] {0x26, 0x20});
                if (session != null) {
                    byte[] mac = session.cmac(iv, Hex.concat(f1, f2, f3, new byte[] {0}));
                    iv = mac;
                    f3 = Hex.concat(f3, Arrays.copyOf(mac, 8));
                }
                pendingFrames = new byte[][] {f2, f3};
                pendingIdx = 0;
                return st(f1, 0xAF);
            }
            case 0x5A: {
                resetAuth();
                int aid = Hex.fromLe24(d, 0);
                if (aid != 0 && !apps.containsKey(aid)) throw new Err(0xA0);
                selected = aid;
                return st(new byte[0], 0);
            }
            case 0xAA:
            case 0x1A: {
                resetAuth();
                Key k = key(d[0] & 0xFF);
                boolean aes = cmd == 0xAA;
                if (k.aes != aes) throw new Err(0xAE);
                pendCipher = aes ? KeyCipher.aes(k.k) : KeyCipher.tdes(k.k);
                int n = aes ? 16 : 8;
                pendRndB = new byte[n];
                rnd.nextBytes(pendRndB);
                pendEk = pendCipher.encryptCbc(new byte[pendCipher.blockSize()], pendRndB);
                pendKey = d[0] & 0xFF;
                pendKeyBytes = k.k.clone();
                return st(pendEk, 0xAF);
            }
            case 0x6A: {
                if (selected != 0) throw new Err(0x1C);
                if ((piccSettings & 0x02) == 0 && authKey != 0) throw new Err(0x9D);
                inMac(cmd, d);
                byte[] o = new byte[0];
                for (int aid : apps.keySet()) o = Hex.concat(o, Hex.le24(aid));
                return out(o);
            }
            case 0xCA: {
                if (selected != 0) throw new Err(0x1C);
                if ((piccSettings & 0x04) == 0 && authKey != 0) throw new Err(0x9D);
                inMac(cmd, d);
                int aid = Hex.fromLe24(d, 0);
                if (apps.containsKey(aid)) throw new Err(0xDE);
                App a = new App();
                a.settings = d[3] & 0xFF;
                int nk = d[4] & 0x0F;
                a.keys = new Key[nk];
                for (int i = 0; i < nk; i++) a.keys[i] = new Key((d[4] & 0x80) != 0);
                apps.put(aid, a);
                return out(new byte[0]);
            }
            case 0xDA: {
                if (selected != 0) throw new Err(0x1C);
                if ((piccSettings & 0x04) == 0 && authKey != 0) throw new Err(0x9D);
                inMac(cmd, d);
                if (apps.remove(Hex.fromLe24(d, 0)) == null) throw new Err(0xA0);
                return out(new byte[0]);
            }
            case 0xCD: {
                App a = app();
                if ((a.settings & 0x04) == 0 && authKey != 0) throw new Err(0x9D);
                inMac(cmd, d);
                int no = d[0];
                if (a.files.containsKey(no)) throw new Err(0xDE);
                FileD f = new FileD();
                f.comm = d[1];
                f.access = (d[2] & 0xFF) | ((d[3] & 0xFF) << 8);
                f.data = new byte[Hex.fromLe24(d, 4)];
                a.files.put(no, f);
                return out(new byte[0]);
            }
            case 0xC4: return changeKey(d);
            case 0x54: {
                if (session == null || authKey != 0) throw new Err(0xAE);
                byte[] p = session.decryptCbc(iv, d);
                iv = session.lastBlock(d);
                byte[] s = new byte[] {p[0]};
                if (!Arrays.equals(Arrays.copyOfRange(p, 1, 5), Crc32Desfire.compute(new byte[] {0x54}, s))) throw new Err(0x1E);
                if (selected == 0) piccSettings = s[0] & 0xFF;
                else app().settings = s[0] & 0xFF;
                return out(new byte[0]);
            }
            case 0x3D: {
                App a = app();
                byte[] hdr = Arrays.copyOf(d, 7);
                FileD f = a.files.get((int) d[0]);
                if (f == null) throw new Err(0xF0);
                int off = Hex.fromLe24(d, 1), len = Hex.fromLe24(d, 4);
                int w = (f.access >> 8) & 0xF, rw = (f.access >> 4) & 0xF;
                boolean free = w == 0xE || rw == 0xE;
                if (!free && authKey != w && authKey != rw) throw new Err(0x9D);
                byte[] payload = Arrays.copyOfRange(d, 7, d.length);
                byte[] data;
                if (session != null && f.comm == 3) {
                    byte[] p = session.decryptCbc(iv, payload);
                    iv = session.lastBlock(payload);
                    data = Arrays.copyOf(p, len);
                    if (!Arrays.equals(Arrays.copyOfRange(p, len, len + 4), Crc32Desfire.compute(new byte[] {0x3D}, hdr, data))) throw new Err(0x1E);
                } else if (session != null && f.comm == 1) {
                    data = Arrays.copyOf(payload, len);
                    byte[] mac = session.cmac(iv, Hex.concat(new byte[] {0x3D}, hdr, data));
                    iv = mac;
                    if (!Arrays.equals(Arrays.copyOf(mac, 8), Arrays.copyOfRange(payload, len, len + 8))) throw new Err(0x1E);
                } else {
                    data = payload;
                    inMac(cmd, d);
                }
                if (off + len > f.data.length) throw new Err(0xBE);
                System.arraycopy(data, 0, f.data, off, len);
                return out(new byte[0]);
            }
            case 0xBD: {
                App a = app();
                FileD f = a.files.get((int) d[0]);
                if (f == null) throw new Err(0xF0);
                int off = Hex.fromLe24(d, 1), len = Hex.fromLe24(d, 4);
                int r = (f.access >> 12) & 0xF, rw = (f.access >> 4) & 0xF;
                boolean free = r == 0xE || rw == 0xE;
                if (!free && authKey != r && authKey != rw) throw new Err(0x9D);
                if (off + len > f.data.length) throw new Err(0xBE);
                inMac(cmd, d);
                byte[] data = Arrays.copyOfRange(f.data, off, off + len);
                if (session != null && f.comm == 3) {
                    byte[] ct = session.encryptCbc(iv, Hex.zeroPad(Hex.concat(data, Crc32Desfire.compute(data, new byte[] {0})), session.blockSize()));
                    iv = session.lastBlock(ct);
                    return st(ct, 0);
                }
                return out(data);
            }
            default:
                throw new Err(0x1C);
        }
    }

    private byte[] finishAuth(byte[] token) throws Err {
        KeyCipher c = pendCipher;
        pendCipher = null;
        int n = pendRndB.length;
        if (token.length != 2 * n) throw new Err(0x7E);
        byte[] p = c.decryptCbc(c.lastBlock(pendEk), token);
        byte[] rndA = Arrays.copyOf(p, n);
        if (!Arrays.equals(Arrays.copyOfRange(p, n, 2 * n), Hex.rotateLeft(pendRndB))) throw new Err(0xAE);
        byte[] resp = c.encryptCbc(c.lastBlock(token), Hex.rotateLeft(rndA));
        byte[] a = rndA, b = pendRndB;
        if (c.type() == KeyCipher.Type.AES) {
            session = KeyCipher.aes(Hex.concat(Hex.slice(a, 0, 4), Hex.slice(b, 0, 4), Hex.slice(a, 12, 16), Hex.slice(b, 12, 16)));
        } else {
            byte[] half = Hex.concat(Hex.slice(a, 0, 4), Hex.slice(b, 0, 4));
            boolean single = Arrays.equals(Hex.slice(pendKeyBytes, 0, 8), Hex.slice(pendKeyBytes, 8, 16));
            session = KeyCipher.tdes(single ? Hex.concat(half, half) : Hex.concat(half, Hex.slice(a, 4, 8), Hex.slice(b, 4, 8)));
        }
        iv = new byte[session.blockSize()];
        authKey = pendKey;
        return st(resp, 0);
    }

    private byte[] changeKey(byte[] d) throws Err {
        if (session == null) throw new Err(0xAE);
        int keyByte = d[0] & 0xFF, no = keyByte & 0x0F;
        Key target = key(no);
        boolean newAes = selected == 0 ? (keyByte & 0x80) != 0 : target.aes;
        if (selected == 0) {
            if (authKey != 0) throw new Err(0x9D);
        } else {
            int ck = (app().settings >> 4) & 0xF;
            if (ck == 0xF) throw new Err(0x9D);
            if (ck == 0xE ? authKey != no : authKey != ck) throw new Err(0x9D);
        }
        byte[] ct = Arrays.copyOfRange(d, 1, d.length);
        byte[] p = session.decryptCbc(iv, ct);
        iv = session.lastBlock(ct);
        int bodyLen = 16 + (newAes ? 1 : 0);
        byte[] body = Arrays.copyOf(p, bodyLen);
        byte[] hdr = new byte[] {(byte) 0xC4, (byte) keyByte};
        if (!Arrays.equals(Arrays.copyOfRange(p, bodyLen, bodyLen + 4), Crc32Desfire.compute(hdr, body))) throw new Err(0x1E);
        boolean changingAuth = no == authKey;
        byte[] newKey;
        if (changingAuth) {
            newKey = Arrays.copyOf(body, 16);
        } else {
            newKey = Hex.xor(Arrays.copyOf(body, 16), target.k);
            if (!Arrays.equals(Arrays.copyOfRange(p, bodyLen + 4, bodyLen + 8), Crc32Desfire.compute(newKey))) throw new Err(0x1E);
        }
        target.k = newKey;
        target.aes = newAes;
        target.ver = newAes ? body[16] & 0xFF : 0;
        if (changingAuth) {
            resetAuth();
            return st(new byte[0], 0);
        }
        return out(new byte[0]);
    }
}
