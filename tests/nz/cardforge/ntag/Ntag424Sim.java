package nz.cardforge.ntag;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import nz.cardforge.desfire.Crc32Desfire;
import nz.cardforge.desfire.DesfireSession;
import nz.cardforge.desfire.Hex;
import nz.cardforge.desfire.KeyCipher;

/**
 * A software NTAG 424 DNA, enough to exercise Verity encoding: ISO select/read/update of the NDEF
 * file, AuthenticateEV2First, ChangeKey and ChangeFileSettings in CommMode.Full, and SUN mirroring
 * (encrypted PICCData + SDM MAC) on every read of the NDEF file.
 */
final class Ntag424Sim implements DesfireSession.Transceiver {
    final byte[] uid;
    final byte[][] keys = new byte[5][];
    final int[] keyVersions = new int[5];
    final byte[] ndef = new byte[256];
    int sdmReadCtr = 0;
    private final SecureRandom rnd = new SecureRandom();

    // file 2 settings
    int fileOption = 0x00;
    int ar0 = 0xE0, ar1 = 0xEE; // RW|Change, Read|Write
    int sdmOptions = 0, sdmAr0 = 0, sdmAr1 = 0, piccOffset = -1, macInputOffset = -1, macOffset = -1;

    // selection + session
    private boolean appSelected, fileSelected;
    private int authKey = -1, cmdCtr;
    private byte[] ti, rndB, pendingKey;
    private int pendingKeyNo = -1;
    private KeyCipher sesEnc, sesMac;

    Ntag424Sim(byte[] uid) {
        this.uid = uid;
        for (int i = 0; i < 5; i++) keys[i] = new byte[16];
    }

    private static byte[] sw(int sw1, int sw2, byte[]... data) {
        return Hex.concat(Hex.concat(data), new byte[] {(byte) sw1, (byte) sw2});
    }

    private void endSession() { authKey = -1; sesEnc = null; sesMac = null; ti = null; }

    @Override
    public byte[] transceive(byte[] a) throws IOException {
        int cla = a[0] & 0xFF, ins = a[1] & 0xFF;
        if (cla == 0x00) return iso(a, ins);
        if (cla == 0x90) {
            byte[] data = a.length > 5 ? Arrays.copyOfRange(a, 5, 5 + (a[4] & 0xFF)) : new byte[0];
            return nativeCmd(ins, data);
        }
        return sw(0x6E, 0x00);
    }

    // ------------------------------------------------------------ ISO

    private byte[] iso(byte[] a, int ins) {
        switch (ins) {
            case 0xA4: {
                int p1 = a[2] & 0xFF;
                byte[] d = Arrays.copyOfRange(a, 5, 5 + (a[4] & 0xFF));
                endSession();
                if (p1 == 0x04) {
                    appSelected = Arrays.equals(d, Ntag424Session.NDEF_APP_DF_NAME);
                    fileSelected = false;
                    return appSelected ? sw(0x90, 0x00) : sw(0x6A, 0x82);
                }
                fileSelected = appSelected && d.length == 2 && ((d[0] & 0xFF) << 8 | (d[1] & 0xFF)) == Ntag424Session.NDEF_FILE_ID;
                return fileSelected ? sw(0x90, 0x00) : sw(0x6A, 0x82);
            }
            case 0xD6: {
                if (!fileSelected) return sw(0x69, 0x86);
                int write = ar1 & 0x0F;
                if (write != 0xE && authKey != write) return sw(0x69, 0x82);
                int off = ((a[2] & 0xFF) << 8) | (a[3] & 0xFF), n = a[4] & 0xFF;
                if (off + n > ndef.length) return sw(0x6B, 0x00);
                System.arraycopy(a, 5, ndef, off, n);
                return sw(0x90, 0x00);
            }
            case 0xB0: {
                if (!fileSelected) return sw(0x69, 0x86);
                int off = ((a[2] & 0xFF) << 8) | (a[3] & 0xFF), n = a[4] & 0xFF;
                if (n == 0) n = 256;
                n = Math.min(n, ndef.length - off);
                byte[] out = Arrays.copyOfRange(ndef, off, off + n);
                if ((fileOption & 0x40) != 0) mirror(out, off);
                return sw(0x90, 0x00, out);
            }
            default:
                return sw(0x6D, 0x00);
        }
    }

    /** SUN: fill PICCData and MAC into the bytes being read. */
    private void mirror(byte[] out, int readOffset) {
        sdmReadCtr++;
        int metaKey = (sdmAr1 >> 4) & 0x0F, fileKey = sdmAr1 & 0x0F;
        byte[] ctrLe = Hex.le24(sdmReadCtr);
        byte[] pad = new byte[5];
        rnd.nextBytes(pad); // a real tag pads PICCData with random bytes
        byte[] plain = Hex.concat(new byte[] {(byte) 0xC7}, uid, ctrLe, pad);
        byte[] picc = KeyCipher.aes(keys[metaKey]).encryptCbc(new byte[16], plain);
        byte[] mac = SunVerifier.mac(keys[fileKey], uid, ctrLe);
        put(out, readOffset, piccOffset, Hex.encode(picc));
        put(out, readOffset, macOffset, Hex.encode(mac));
    }

    private static void put(byte[] out, int readOffset, int at, String ascii) {
        byte[] b = ascii.getBytes();
        for (int i = 0; i < b.length; i++) {
            int idx = at + i - readOffset;
            if (idx >= 0 && idx < out.length) out[idx] = b[i];
        }
    }

    // ------------------------------------------------------------ native

    private byte[] nativeCmd(int ins, byte[] data) {
        if (!appSelected) return sw(0x91, 0xA0);
        switch (ins) {
            case 0x71: {
                endSession();
                pendingKeyNo = data[0] & 0xFF;
                if (pendingKeyNo > 4) return sw(0x91, 0x40);
                pendingKey = keys[pendingKeyNo];
                rndB = new byte[16];
                rnd.nextBytes(rndB);
                return sw(0x91, 0xAF, KeyCipher.aes(pendingKey).encryptCbc(new byte[16], rndB));
            }
            case 0xAF: {
                if (pendingKey == null || data.length != 32) return sw(0x91, 0x7E);
                KeyCipher k = KeyCipher.aes(pendingKey);
                byte[] p = k.decryptCbc(new byte[16], data);
                byte[] rndA = Arrays.copyOf(p, 16);
                if (!Arrays.equals(Arrays.copyOfRange(p, 16, 32), Hex.rotateLeft(rndB))) {
                    pendingKey = null;
                    return sw(0x91, 0xAE);
                }
                ti = new byte[4];
                rnd.nextBytes(ti);
                byte[][] sk = Ntag424Session.sessionKeys(pendingKey, rndA, rndB);
                sesEnc = KeyCipher.aes(sk[0]);
                sesMac = KeyCipher.aes(sk[1]);
                authKey = pendingKeyNo;
                cmdCtr = 0;
                pendingKey = null;
                byte[] resp = Hex.concat(ti, Hex.rotateLeft(rndA), new byte[6], new byte[6]);
                return sw(0x91, 0x00, k.encryptCbc(new byte[16], resp));
            }
            case 0xC4:
            case 0x5F:
                return fullCommand(ins, data);
            default:
                return sw(0x91, 0x1C);
        }
    }

    private byte[] ctr() { return new byte[] {(byte) cmdCtr, (byte) (cmdCtr >> 8)}; }

    private byte[] okWithMac() {
        cmdCtr++;
        byte[] mac = Ntag424Session.truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {0x00}, ctr(), ti)));
        return sw(0x91, 0x00, mac);
    }

    private byte[] fullCommand(int ins, byte[] data) {
        if (sesEnc == null) return sw(0x91, 0xAE);
        byte[] header = Arrays.copyOf(data, 1);
        byte[] enc = Arrays.copyOfRange(data, 1, data.length - 8);
        byte[] mac = Arrays.copyOfRange(data, data.length - 8, data.length);
        byte[] want = Ntag424Session.truncateMac(sesMac.cmac(new byte[16], Hex.concat(new byte[] {(byte) ins}, ctr(), ti, header, enc)));
        if (!Arrays.equals(mac, want)) { endSession(); return sw(0x91, 0x1E); }
        byte[] ivc = sesEnc.encryptCbc(new byte[16], Hex.concat(new byte[] {(byte) 0xA5, 0x5A}, ti, ctr(), new byte[8]));
        byte[] p = sesEnc.decryptCbc(ivc, enc);
        int end = p.length - 1;
        while (end >= 0 && p[end] == 0) end--;
        if (end < 0 || (p[end] & 0xFF) != 0x80) { endSession(); return sw(0x91, 0x1E); }
        p = Arrays.copyOf(p, end);

        if (ins == 0xC4) {
            int keyNo = header[0] & 0xFF;
            if (authKey != 0) return sw(0x91, 0x9D);
            if (keyNo == authKey) {
                keys[keyNo] = Arrays.copyOf(p, 16);
                keyVersions[keyNo] = p[16] & 0xFF;
                endSession();
                return sw(0x91, 0x00);
            }
            byte[] newKey = Hex.xor(Arrays.copyOf(p, 16), keys[keyNo]);
            if (!Arrays.equals(Arrays.copyOfRange(p, 17, 21), Crc32Desfire.compute(newKey))) return sw(0x91, 0x1E);
            keys[keyNo] = newKey;
            keyVersions[keyNo] = p[16] & 0xFF;
            return okWithMac();
        }
        // ChangeFileSettings, file 2 only
        if ((header[0] & 0xFF) != 0x02) return sw(0x91, 0xF0);
        if (authKey != (ar0 & 0x0F)) return sw(0x91, 0x9D);
        fileOption = p[0] & 0xFF;
        ar0 = p[1] & 0xFF;
        ar1 = p[2] & 0xFF;
        if ((fileOption & 0x40) != 0) {
            sdmOptions = p[3] & 0xFF;
            sdmAr0 = p[4] & 0xFF;
            sdmAr1 = p[5] & 0xFF;
            piccOffset = Hex.fromLe24(p, 6);
            macInputOffset = Hex.fromLe24(p, 9);
            macOffset = Hex.fromLe24(p, 12);
        } else {
            sdmOptions = 0; piccOffset = macInputOffset = macOffset = -1;
        }
        return okWithMac();
    }
}
