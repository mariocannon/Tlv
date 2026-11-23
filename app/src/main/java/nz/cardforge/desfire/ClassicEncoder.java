package nz.cardforge.desfire;

import java.io.IOException;
import java.util.Arrays;

/**
 * MIFARE Classic 1K/4K credential encoding for ICT readers.
 *
 * Layout in the chosen sector (default sector 1 = blocks 4..7):
 *   block 4 : credential (site, card, 'C' 'F' format id, zero padded)   <- ICT "Block" setting
 *   block 5,6: zeros
 *   block 7 : trailer = Key A | 78 77 88 69 | Key B
 * Access bits 78 77 88: data blocks readable with A or B, writable only with B;
 * Key A / Key B / access bits changeable only with B. So the reader's Key A can read but never write.
 */
public final class ClassicEncoder implements CredentialEncoder {

    /** Minimal card abstraction (implemented over android.nfc.tech.MifareClassic, and by the test simulator). */
    public interface ClassicCard {
        int sectorCount();
        /** @return true if authenticated; implementations must recover (reconnect) after a failed attempt. */
        boolean authA(int sector, byte[] key) throws IOException;
        boolean authB(int sector, byte[] key) throws IOException;
        byte[] readBlock(int block) throws IOException;
        void writeBlock(int block, byte[] data) throws IOException;
    }

    public static final byte[] ACCESS_LOCKED = Hex.decode("78778869");   // read A|B, write B, keys B
    public static final byte[] ACCESS_FACTORY = Hex.decode("FF078069");  // transport configuration
    public static final byte[] KEY_FF = Hex.decode("FFFFFFFFFFFF");

    /** Well-known default/transport keys tried on blank cards. */
    static final byte[][] DEFAULT_KEYS = {
            KEY_FF, Hex.decode("000000000000"), Hex.decode("A0A1A2A3A4A5"),
            Hex.decode("B0B1B2B3B4B5"), Hex.decode("D3F7D3F7D3F7")};

    public static boolean isWeakKey(byte[] k) {
        for (byte[] d : DEFAULT_KEYS) if (Arrays.equals(d, k)) return true;
        return false;
    }

    private final ClassicCard card;
    private final CardProfile p;
    private final byte[] uid;
    private final CardEncoder.Log log;

    public ClassicEncoder(ClassicCard card, CardProfile profile, byte[] uid, CardEncoder.Log log) {
        this.card = card;
        this.p = profile;
        this.uid = uid;
        this.log = log;
    }

    private int block0() { return p.classicBlock(); }

    private int trailer() { return p.classicBlock() + 3; }

    private void checkCard() throws DesfireException {
        int sectors = card.sectorCount();
        if (p.classicSector >= sectors) throw new DesfireException("Card has only " + sectors + " sectors");
        log.step("Card: MIFARE Classic " + (sectors >= 40 ? "4K" : sectors >= 16 ? "1K" : "Mini") + ", UID " + Hex.encode(uid));
    }

    /** @return true if the sector already uses our keys (authenticated with Key B), false if blank (authenticated with a default key). */
    private boolean authForWrite() throws IOException, DesfireException {
        int s = p.classicSector;
        if (card.authB(s, p.classicKeyB)) {
            log.step("Sector " + s + " already uses your keys");
            return true;
        }
        for (byte[] k : DEFAULT_KEYS) {
            if (card.authA(s, k) || card.authB(s, k)) {
                log.step("Sector " + s + " is blank (default key " + Hex.encode(k) + ")");
                return false;
            }
        }
        throw new DesfireException("Sector " + p.classicSector + " uses unknown keys - this card belongs to another system");
    }

    private void write(int block, byte[] data) throws IOException, DesfireException {
        try {
            card.writeBlock(block, data);
        } catch (IOException e) {
            throw new DesfireException("Write to block " + block + " was refused (" + e.getMessage() + ")");
        }
    }

    public Credential encode(Credential cred, boolean overwrite) throws IOException, DesfireException {
        p.validate();
        checkCard();
        boolean ours = authForWrite();
        if (ours && !overwrite) throw new DesfireException("Card is already encoded. Use Verify, or tick Overwrite.");

        log.step("Writing credential to block " + block0() + ": " + cred);
        write(block0(), cred.toFile(16));
        write(block0() + 1, new byte[16]);
        write(block0() + 2, new byte[16]);

        log.step("Setting Key A (reader) / Key B (phone) and locking access bits");
        write(trailer(), Hex.concat(p.classicKeyA, ACCESS_LOCKED, p.classicKeyB));

        log.step("Verifying with Key A (as the reader will)");
        Credential back = verify();
        if (back.site != cred.site || back.card != cred.card || back.format != cred.format)
            throw new DesfireException("Verify mismatch: wrote " + cred + " read " + back);
        log.step("Done ✔");
        return back;
    }

    public Credential verify() throws IOException, DesfireException {
        if (!card.authA(p.classicSector, p.classicKeyA))
            throw new DesfireException("Key A rejected - card not encoded with these keys");
        return Credential.parse(card.readBlock(block0()));
    }

    public void wipe() throws IOException, DesfireException {
        checkCard();
        if (!card.authB(p.classicSector, p.classicKeyB)) {
            throw new DesfireException("Key B rejected - card isn't encoded with these keys (or is already blank)");
        }
        log.step("Clearing blocks " + block0() + "-" + (block0() + 2));
        for (int i = 0; i < 3; i++) write(block0() + i, new byte[16]);
        log.step("Restoring factory keys FFFFFFFFFFFF and access bits");
        write(trailer(), Hex.concat(KEY_FF, ACCESS_FACTORY, KEY_FF));
        log.step("Card wiped ✔");
    }
}
