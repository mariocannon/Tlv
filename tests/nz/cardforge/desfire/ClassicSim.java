package nz.cardforge.desfire;

import java.io.IOException;
import java.util.Arrays;

/** Software MIFARE Classic 1K enforcing keys and access conditions (enough to catch bricking trailers). */
final class ClassicSim implements ClassicEncoder.ClassicCard {
    final byte[] uid = Hex.decode("A1B2C3D4");
    final byte[][] blocks = new byte[64][16];
    private int authSector = -1;
    private boolean authIsB;
    int failedAuths = 0;

    ClassicSim() {
        for (int s = 0; s < 16; s++) blocks[s * 4 + 3] = Hex.concat(ClassicEncoder.KEY_FF, ClassicEncoder.ACCESS_FACTORY, ClassicEncoder.KEY_FF);
        blocks[0] = Hex.decode("A1B2C3D4E40804006263646566676869");
    }

    @Override public int sectorCount() { return 16; }

    private boolean auth(int sector, byte[] key, boolean b) {
        byte[] t = blocks[sector * 4 + 3];
        byte[] k = b ? Arrays.copyOfRange(t, 10, 16) : Arrays.copyOf(t, 6);
        if (Arrays.equals(k, key)) {
            authSector = sector;
            authIsB = b;
            return true;
        }
        authSector = -1;
        failedAuths++;
        return false;
    }

    @Override public boolean authA(int sector, byte[] key) { return auth(sector, key, false); }

    @Override public boolean authB(int sector, byte[] key) { return auth(sector, key, true); }

    /** Returns C1C2C3 as a 3-bit value for block index 0..3 of the sector; throws if access bytes are inconsistent. */
    static int cond(byte[] trailer, int idx) throws IOException {
        int b6 = trailer[6] & 0xFF, b7 = trailer[7] & 0xFF, b8 = trailer[8] & 0xFF;
        int c1 = b7 >> 4, c2 = b8 & 0xF, c3 = b8 >> 4;
        if ((~c1 & 0xF) != (b6 & 0xF) || (~c2 & 0xF) != (b6 >> 4) || (~c3 & 0xF) != (b7 & 0xF))
            throw new IOException("sector bricked: inconsistent access bits");
        return (((c1 >> idx) & 1) << 2) | (((c2 >> idx) & 1) << 1) | ((c3 >> idx) & 1);
    }

    private int sectorOf(int block) throws IOException {
        int s = block / 4;
        if (s != authSector) throw new IOException("not authenticated for sector " + s);
        return s;
    }

    @Override
    public byte[] readBlock(int block) throws IOException {
        int s = sectorOf(block);
        int c = cond(blocks[s * 4 + 3], block % 4);
        if (block % 4 == 3) {
            byte[] t = blocks[block].clone();
            Arrays.fill(t, 0, 6, (byte) 0); // Key A never readable
            return t;
        }
        boolean ok = (c == 0b000 || c == 0b010 || c == 0b100 || c == 0b110 || c == 0b001) || (authIsB && (c == 0b011 || c == 0b101));
        if (!ok) throw new IOException("read denied");
        return blocks[block].clone();
    }

    @Override
    public void writeBlock(int block, byte[] data) throws IOException {
        if (data.length != 16) throw new IOException("block must be 16 bytes");
        int s = sectorOf(block);
        int c = cond(blocks[s * 4 + 3], block % 4);
        boolean ok;
        if (block % 4 == 3) {
            ok = (c == 0b001 && !authIsB) || (c == 0b011 && authIsB) || (c == 0b100 && authIsB);
            if (ok) cond(data, 0); // validate the new trailer's access bits (a bad one bricks a real card)
        } else {
            ok = c == 0b000 || (authIsB && (c == 0b100 || c == 0b110 || c == 0b011));
        }
        if (!ok) throw new IOException("write denied (cond " + Integer.toBinaryString(c) + (authIsB ? " key B)" : " key A)"));
        blocks[block] = data.clone();
    }
}
