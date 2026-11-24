package nz.cardforge.ntag;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import nz.cardforge.desfire.DesfireSession;
import nz.cardforge.desfire.Hex;

/** Simulated NTAG213/215/216 with the UID + NFC counter mirror, per the NXP datasheet. */
final class Ntag21xSim implements DesfireSession.Transceiver {
    final byte[] mem;
    final byte[] uid;
    final int sizeByte, cfg0, lastUser;
    int counter = 0;
    boolean readSincePowerUp = false;

    Ntag21xSim(int sizeByte, byte[] uid) {
        this.sizeByte = sizeByte; this.uid = uid;
        Ntag21xEncoder.Model m = sizeByte == 0x0F ? Ntag21xEncoder.NTAG213 : sizeByte == 0x11 ? Ntag21xEncoder.NTAG215 : Ntag21xEncoder.NTAG216;
        cfg0 = m.cfg0Page; lastUser = m.lastUserPage;
        mem = new byte[(cfg0 + 4) * 4];
        System.arraycopy(uid, 0, mem, 0, 3); System.arraycopy(uid, 3, mem, 4, 4);
        mem[12] = (byte) 0xE1; mem[13] = 0x10; mem[14] = (byte) m.ccSize; // factory CC
        mem[16] = 0x03; mem[17] = 0x00; mem[18] = (byte) 0xFE;            // empty NDEF
        mem[cfg0 * 4] = 0x04;      // MIRROR: STRG_MOD_EN set, mirror off (factory)
        mem[cfg0 * 4 + 3] = (byte) 0xFF; // AUTH0 off
    }

    void powerCycle() { readSincePowerUp = false; }

    @Override public byte[] transceive(byte[] c) {
        switch (c[0] & 0xFF) {
            case 0x60: return new byte[] { 0x00, 0x04, 0x04, 0x02, 0x01, 0x00, (byte) sizeByte, 0x03 };
            case 0x30: {
                int pg = c[1] & 0xFF;
                if (pg > cfg0 + 3) return new byte[] { 0x00 }; // NAK
                int mc = mem[cfg0 * 4] & 0xFF;
                if (!readSincePowerUp) { readSincePowerUp = true; if ((mem[cfg0 * 4 + 4] & 0x10) != 0) counter++; }
                byte[] view = mem.clone();
                if ((mc >> 6) == 3) {
                    String s = Hex.encode(uid) + "x" + String.format("%06X", counter);
                    int at = (mem[cfg0 * 4 + 2] & 0xFF) * 4 + ((mc >> 4) & 3);
                    if (at >= 16) System.arraycopy(s.getBytes(StandardCharsets.US_ASCII), 0, view, at, 21);
                }
                Arrays.fill(view, (cfg0 + 2) * 4, (cfg0 + 4) * 4, (byte) 0); // PWD/PACK read as 0
                byte[] r = new byte[16];
                for (int i = 0; i < 16; i++) { int a = (pg * 4 + i) % view.length; r[i] = view[a]; }
                return r;
            }
            case 0xA2: {
                int pg = c[1] & 0xFF;
                if (pg < 3 || pg > cfg0 + 3) return new byte[] { 0x00 };
                if ((mem[cfg0 * 4 + 3] & 0xFF) <= pg) return new byte[] { 0x00 }; // password protected
                if (pg == 3) { for (int i = 0; i < 4; i++) mem[12 + i] |= c[2 + i]; } // OTP
                else System.arraycopy(c, 2, mem, pg * 4, 4);
                return new byte[] { 0x0A };
            }
            default: return new byte[] { 0x00 };
        }
    }
}
