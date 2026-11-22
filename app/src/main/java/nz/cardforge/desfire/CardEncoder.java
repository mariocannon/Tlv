package nz.cardforge.desfire;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/** High-level flows: encode a blank card, verify it, and wipe it back to factory state. */
public final class CardEncoder {

    public interface Log {
        void step(String message);
    }

    private static final byte[] ZERO16 = new byte[16];

    private enum PiccKey { CUSTOM_AES, DEFAULT_DES, DEFAULT_AES }

    private final DesfireSession s;
    private final CardProfile p;
    private final byte[] uid;
    private final Log log;

    public CardEncoder(DesfireSession session, CardProfile profile, byte[] uid, Log log) {
        this.s = session;
        this.p = profile;
        this.uid = uid;
        this.log = log;
    }

    private byte[] k(byte[] master) { return p.cardKey(master, uid, p.aid); }

    private byte[] piccKey() { return p.cardKey(p.piccMasterKey, uid, 0x000000); }

    private void checkDesfire() throws IOException, DesfireException {
        s.selectApplication(0);
        byte[] v = s.getVersion();
        if (v.length < 7 || v[0] != 0x04 || v[1] != 0x01) throw new DesfireException("Not a MIFARE DESFire card");
        int major = v[3] & 0xFF;
        String gen = major == 0x00 ? "EV0 (unsupported)" : major == 0x01 ? "EV1" : major == 0x12 ? "EV2" : major == 0x33 ? "EV3" : String.format("v%02X", major);
        if (major == 0x00) throw new DesfireException("DESFire EV0 (MF3ICD40) has no AES support");
        int storageExp = (v[5] & 0xFF) >> 1;
        log.step("Card: DESFire " + gen + ", ~" + (1 << storageExp) + " bytes, UID " + Hex.encode(uid));
    }

    /** Authenticate with the card (PICC) master key, trying the custom key and the factory defaults. */
    private PiccKey authPicc() throws IOException, DesfireException {
        PiccKey[] order = p.lockPicc
                ? new PiccKey[] {PiccKey.CUSTOM_AES, PiccKey.DEFAULT_DES, PiccKey.DEFAULT_AES}
                : new PiccKey[] {PiccKey.DEFAULT_DES, PiccKey.DEFAULT_AES, PiccKey.CUSTOM_AES};
        DesfireException last = null;
        for (PiccKey kind : order) {
            try {
                s.selectApplication(0);
                switch (kind) {
                    case CUSTOM_AES: s.authenticateAes(0, piccKey()); break;
                    case DEFAULT_DES: s.authenticateIso(0, ZERO16); break;
                    default: s.authenticateAes(0, ZERO16);
                }
                log.step("Card master key: " + (kind == PiccKey.CUSTOM_AES ? "your custom key" : "factory default"));
                return kind;
            } catch (DesfireException e) {
                last = e;
            }
        }
        throw new DesfireException("Card master key unknown - this card belongs to another system (" + (last == null ? "" : last.getMessage()) + ")");
    }

    public Credential encode(Credential cred, boolean overwrite) throws IOException, DesfireException {
        p.validate();
        checkDesfire();
        PiccKey picc = authPicc();

        List<Integer> aids = s.getApplicationIds();
        if (aids.contains(p.aid)) {
            if (!overwrite) throw new DesfireException(String.format("Card already has application %06X. Use Verify, or tick Overwrite.", p.aid));
            log.step("Deleting existing application");
            s.deleteApplication(p.aid);
        }

        log.step(String.format("Creating application %06X (3 AES keys)", p.aid));
        s.createApplication(p.aid, CardProfile.APP_KEY_SETTINGS, 0x80 | CardProfile.APP_KEY_COUNT);

        if (p.lockPicc && picc != PiccKey.CUSTOM_AES) {
            log.step("Locking card master key");
            s.changeKey(0x80, piccKey(), null, p.keyVersion, true); // AES key type at PICC level
            s.selectApplication(0);
            s.authenticateAes(0, piccKey());
            s.changeKeySettings(CardProfile.PICC_LOCKED_SETTINGS);
        }

        s.selectApplication(p.aid);
        s.authenticateAes(CardProfile.KEY_APP_MASTER, ZERO16);
        log.step("Creating file " + p.fileNo + " (" + p.comm + ")");
        s.createStdDataFile(p.fileNo, p.comm, CardProfile.ACCESS_RIGHTS, p.fileSize);

        log.step("Setting read / write / master keys");
        s.changeKey(CardProfile.KEY_READ, k(p.readKey), ZERO16, p.keyVersion, true);
        s.changeKey(CardProfile.KEY_WRITE, k(p.writeKey), ZERO16, p.keyVersion, true);
        s.changeKey(CardProfile.KEY_APP_MASTER, k(p.appMasterKey), null, p.keyVersion, true);

        log.step("Writing credential: " + cred);
        byte[] file = cred.toFile(p.fileSize);
        s.selectApplication(p.aid);
        s.authenticateAes(CardProfile.KEY_WRITE, k(p.writeKey));
        s.writeData(p.fileNo, 0, file, p.comm);

        log.step("Verifying with the read key (as the reader will)");
        Credential back = verify();
        if (back.site != cred.site || back.card != cred.card || back.format != cred.format)
            throw new DesfireException("Verify mismatch: wrote " + cred + " read " + back);
        log.step("Done ✔");
        return back;
    }

    /** Read the credential exactly the way the reader does: select AID, auth with key 1, read file. */
    public Credential verify() throws IOException, DesfireException {
        s.selectApplication(p.aid);
        s.authenticateAes(CardProfile.KEY_READ, k(p.readKey));
        byte[] data = s.readData(p.fileNo, 0, p.fileSize, p.comm);
        return Credential.parse(data);
    }

    /** Delete the application and (if locked) restore the factory DES master key, so the card can be reused. */
    public void wipe() throws IOException, DesfireException {
        checkDesfire();
        PiccKey picc = authPicc();
        List<Integer> aids = s.getApplicationIds();
        if (aids.contains(p.aid)) {
            log.step(String.format("Deleting application %06X", p.aid));
            s.deleteApplication(p.aid);
        } else {
            log.step(String.format("Application %06X not on card", p.aid));
        }
        if (picc == PiccKey.CUSTOM_AES) {
            log.step("Restoring factory card master key");
            s.changeKeySettings(CardProfile.PICC_FACTORY_SETTINGS);
            s.changeKey(0x00, ZERO16, null, 0, false); // back to DES 00..00
        } else if (picc == PiccKey.DEFAULT_AES) {
            s.changeKey(0x00, ZERO16, null, 0, false);
        }
        log.step("Card wiped ✔");
    }

    static boolean same(byte[] a, byte[] b) { return Arrays.equals(a, b); }
}
