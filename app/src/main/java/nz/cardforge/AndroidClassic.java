package nz.cardforge;

import android.nfc.TagLostException;
import android.nfc.tech.MifareClassic;

import java.io.IOException;

import nz.cardforge.desfire.ClassicEncoder;

/** Adapts android.nfc.tech.MifareClassic to the core ClassicCard interface. */
final class AndroidClassic implements ClassicEncoder.ClassicCard {
    private final MifareClassic m;

    AndroidClassic(MifareClassic m) { this.m = m; }

    @Override public int sectorCount() { return m.getSectorCount(); }

    @Override public boolean authA(int sector, byte[] key) throws IOException { return auth(sector, key, false); }

    @Override public boolean authB(int sector, byte[] key) throws IOException { return auth(sector, key, true); }

    private boolean auth(int sector, byte[] key, boolean useB) throws IOException {
        boolean ok;
        try {
            ok = useB ? m.authenticateSectorWithKeyB(sector, key) : m.authenticateSectorWithKeyA(sector, key);
        } catch (TagLostException e) {
            throw e;
        } catch (IOException e) {
            ok = false;
        }
        if (!ok) {
            // A failed Crypto1 auth halts the card; reconnect before the next attempt.
            try {
                m.close();
            } catch (IOException ignored) {
            }
            m.connect();
            m.setTimeout(1000);
        }
        return ok;
    }

    @Override public byte[] readBlock(int block) throws IOException { return m.readBlock(block); }

    @Override public void writeBlock(int block, byte[] data) throws IOException { m.writeBlock(block, data); }
}
