package nz.cardforge.desfire;

import java.security.SecureRandom;

/**
 * Everything the phone and the reader must agree on. The reader only needs: AID, file number,
 * read key (key 1), comm mode, diversification settings, value offset/length.
 */
public final class CardProfile {
    public static final int KEY_APP_MASTER = 0, KEY_READ = 1, KEY_WRITE = 2;
    public static final int APP_KEY_COUNT = 3;
    /** Read=key1, Write=key2, ReadWrite=key2, Change access rights=key0 */
    public static final int ACCESS_RIGHTS = (KEY_READ << 12) | (KEY_WRITE << 8) | (KEY_WRITE << 4) | KEY_APP_MASTER;
    /** App key settings: master key changeable, free directory list, create/delete needs master, config changeable. */
    public static final int APP_KEY_SETTINGS = 0x0B;
    /** PICC settings when locked: same as above at card level (app creation requires the PICC master key). */
    public static final int PICC_LOCKED_SETTINGS = 0x0B;
    public static final int PICC_FACTORY_SETTINGS = 0x0F;

    public int aid = 0xF5AC01;
    public int fileNo = 1;
    public int fileSize = 32;
    public DesfireSession.Comm comm = DesfireSession.Comm.ENC;
    public Credential.Format format = Credential.Format.W34;

    public byte[] piccMasterKey = new byte[16];
    public byte[] appMasterKey = new byte[16];
    public byte[] readKey = new byte[16];
    public byte[] writeKey = new byte[16];

    public boolean diversify = false;
    public byte[] systemId = new byte[0]; // AV2 system identifier (ICT exposes none; leave empty)
    public boolean lockPicc = false;
    public int keyVersion = 1;

    public static CardProfile generate(SecureRandom rnd) {
        CardProfile p = new CardProfile();
        rnd.nextBytes(p.piccMasterKey);
        rnd.nextBytes(p.appMasterKey);
        rnd.nextBytes(p.readKey);
        rnd.nextBytes(p.writeKey);
        return p;
    }

    /** Key as stored on a specific card (diversified per UID if enabled). */
    public byte[] cardKey(byte[] masterKey, byte[] uid, int aidForDiv) {
        if (!diversify) return masterKey.clone();
        if (uid == null || uid.length == 0) throw new IllegalArgumentException("Diversification needs the card UID");
        return KeyDiversifier.aes128(masterKey, KeyDiversifier.input(uid, aidForDiv, systemId));
    }

    public void validate() {
        if (aid <= 0 || aid > 0xFFFFFF) throw new IllegalArgumentException("AID must be 000001..FFFFFF");
        if (aid == 0xFFFFFF) throw new IllegalArgumentException("AID FFFFFF is reserved");
        if (fileNo < 0 || fileNo > 31) throw new IllegalArgumentException("File number must be 0..31");
        for (byte[] k : new byte[][] {piccMasterKey, appMasterKey, readKey, writeKey})
            if (k == null || k.length != 16) throw new IllegalArgumentException("All keys must be 16 bytes (32 hex chars)");
        if (ictKeyslot < 2 || ictKeyslot > 4) throw new IllegalArgumentException("ICT keyslot must be 2..4");
        if (systemId.length > 31 - 10) throw new IllegalArgumentException("System ID max 21 bytes");
        if (isZero(appMasterKey) || isZero(readKey) || isZero(writeKey))
            throw new IllegalArgumentException("Keys are still all-zero. Generate keys first.");
    }

    static boolean isZero(byte[] k) {
        for (byte b : k) if (b != 0) return false;
        return true;
    }

    // ICT reader slots (from the ICT Card Reader Configuration Guide custom credential example)
    public int ictKeyslot = 2;          // 0 and 1 reserved; 2-4 available
    public int ictCredentialSlot = 7;   // 5-8 available
    public int ictFormatSlot = 6;
    public int ictLinkageSlot = 6;

    /** ICT Keyslot hex TLV: 03 11 <16-byte AES read key> <keyslot>. */
    public String ictKeyslotTlv() {
        return "0311" + Hex.encode(readKey) + String.format("%02X", ictKeyslot);
    }

    public String ictFormatHex() {
        return Hex.encode(format.ictFormatString().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** Step-by-step settings for the Protege Config App. */
    public String ictConfig(boolean includeKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("ICT reader config (Protege Config App)\n");
        sb.append("======================================\n\n");
        sb.append("1) Hex TLV - load the DESFire read key\n");
        sb.append("   ").append(includeKey ? ictKeyslotTlv() : "0311" + "<read key hidden>" + String.format("%02X", ictKeyslot)).append("\n");
        sb.append(String.format("   (type 03, length 11, AES-128 read key, keyslot %d)%n%n", ictKeyslot));
        sb.append("2) Access Credentials\n");
        sb.append(String.format("   Slot             : %d%n", ictCredentialSlot));
        sb.append("   Credential Type  : Mifare DESFire\n");
        sb.append(String.format("   App ID           : %06X%n", aid));
        sb.append(String.format("   AES Keyslot      : %d%n", ictKeyslot));
        sb.append(String.format("   File Number      : %d%n", fileNo));
        sb.append(String.format("   Key Number       : %d%n", KEY_READ));
        sb.append(String.format("   Diversification  : %s%n%n", diversify ? "AV2 Diversification" : "No diversification"));
        sb.append("3) Custom Card Format Slots\n");
        sb.append(String.format("   Slot             : %d%n", ictFormatSlot));
        sb.append(String.format("   Format (ASCII hex): %s   = %s%n%n", ictFormatHex(), format.ictFormatString()));
        sb.append("4) Card Linkages\n");
        sb.append(String.format("   Linkage Slot     : %d%n", ictLinkageSlot));
        sb.append("   Flags            : none (no extra AES-256 data layer)\n");
        sb.append(String.format("   Keyslot          : %d%n", ictKeyslot));
        sb.append(String.format("   Access Cred Slot : %d%n", ictCredentialSlot));
        sb.append(String.format("   Format Slot      : %d%n%n", ictFormatSlot));
        sb.append("5) Output Mode: OSDP\n");
        sb.append("6) tSec readers only, for EV2/EV3 cards - Hex TLV: 180106 (ISO14443 gain 6)\n\n");
        sb.append("Apply within 2 minutes of power-cycling the reader.\n");
        sb.append(String.format("Card data: %s, big-endian, from byte 0. Comm mode: %s.%n", format.label,
                comm == DesfireSession.Comm.ENC ? "encrypted" : comm == DesfireSession.Comm.MAC ? "MAC" : "plain"));
        return sb.toString();
    }
}
