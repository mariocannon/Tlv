package nz.cardforge.desfire;

import java.security.SecureRandom;

/**
 * Everything the phone and the reader must agree on, for either card type:
 *  - DESFire: AID, file, AES read key (key 1), comm mode, diversification
 *  - MIFARE Classic: sector/block, Key A = read key (reader), Key B = write key (phone only)
 */
public final class CardProfile {
    public enum CardType { DESFIRE, CLASSIC }

    public static final int KEY_APP_MASTER = 0, KEY_READ = 1, KEY_WRITE = 2;
    public static final int APP_KEY_COUNT = 3;
    /** Read=key1, Write=key2, ReadWrite=key2, Change access rights=key0 */
    public static final int ACCESS_RIGHTS = (KEY_READ << 12) | (KEY_WRITE << 8) | (KEY_WRITE << 4) | KEY_APP_MASTER;
    /** App key settings: master key changeable, free directory list, create/delete needs master, config changeable. */
    public static final int APP_KEY_SETTINGS = 0x0B;
    /** PICC settings when locked: same as above at card level (app creation requires the PICC master key). */
    public static final int PICC_LOCKED_SETTINGS = 0x0B;
    public static final int PICC_FACTORY_SETTINGS = 0x0F;

    public CardType cardType = CardType.DESFIRE;

    // ---- DESFire
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

    // ---- MIFARE Classic
    /** Sector holding the credential (1..15; sector 0 holds the manufacturer block). Data goes in its first block. */
    public int classicSector = 1;
    public byte[] classicKeyA = new byte[6]; // read key -> reader keyslot
    public byte[] classicKeyB = new byte[6]; // write key -> phone only

    // ---- Phone (HCE) credential
    /** Optional AES-256 data-layer key (ICT card linkage "AES 256 Decrypt CBC" + "IV in first block"). */
    public byte[] mobileDataKey = new byte[32];
    public int ictDataKeyslot = 3;
    public int ictMobileCredentialSlot = 8;
    public int ictMobileLinkageSlot = 7;

    public static CardProfile generate(SecureRandom rnd) {
        CardProfile p = new CardProfile();
        rnd.nextBytes(p.piccMasterKey);
        rnd.nextBytes(p.appMasterKey);
        rnd.nextBytes(p.readKey);
        rnd.nextBytes(p.writeKey);
        p.generateClassicKeys(rnd);
        rnd.nextBytes(p.mobileDataKey);
        return p;
    }

    public void generateClassicKeys(SecureRandom rnd) {
        do {
            rnd.nextBytes(classicKeyA);
            rnd.nextBytes(classicKeyB);
        } while (ClassicEncoder.isWeakKey(classicKeyA) || ClassicEncoder.isWeakKey(classicKeyB)
                || java.util.Arrays.equals(classicKeyA, classicKeyB));
    }

    /** Absolute MIFARE Classic block number of the credential (first block of the sector, 1K/4K low sectors). */
    public int classicBlock() { return classicSector * 4; }

    /** Key as stored on a specific card (diversified per UID if enabled). */
    public byte[] cardKey(byte[] masterKey, byte[] uid, int aidForDiv) {
        if (!diversify) return masterKey.clone();
        if (uid == null || uid.length == 0) throw new IllegalArgumentException("Diversification needs the card UID");
        return KeyDiversifier.aes128(masterKey, KeyDiversifier.input(uid, aidForDiv, systemId));
    }

    public void validate() {
        if (ictKeyslot < 2 || ictKeyslot > 4) throw new IllegalArgumentException("ICT keyslot must be 2..4");
        if (cardType == CardType.CLASSIC) {
            if (classicSector < 1 || classicSector > 15) throw new IllegalArgumentException("Classic sector must be 1..15");
            if (classicKeyA == null || classicKeyA.length != 6 || classicKeyB == null || classicKeyB.length != 6)
                throw new IllegalArgumentException("Classic keys must be 6 bytes (12 hex chars)");
            if (ClassicEncoder.isWeakKey(classicKeyA) || ClassicEncoder.isWeakKey(classicKeyB))
                throw new IllegalArgumentException("Classic keys are blank/default. Generate keys first.");
            if (java.util.Arrays.equals(classicKeyA, classicKeyB))
                throw new IllegalArgumentException("Classic Key A and Key B must differ");
            return;
        }
        if (aid <= 0 || aid > 0xFFFFFF) throw new IllegalArgumentException("AID must be 000001..FFFFFF");
        if (aid == 0xFFFFFF) throw new IllegalArgumentException("AID FFFFFF is reserved");
        if (fileNo < 0 || fileNo > 31) throw new IllegalArgumentException("File number must be 0..31");
        for (byte[] k : new byte[][] {piccMasterKey, appMasterKey, readKey, writeKey})
            if (k == null || k.length != 16) throw new IllegalArgumentException("All keys must be 16 bytes (32 hex chars)");
        if (systemId.length > 31 - 10) throw new IllegalArgumentException("System ID max 21 bytes");
        if (isZero(appMasterKey) || isZero(readKey) || isZero(writeKey))
            throw new IllegalArgumentException("Keys are still all-zero. Generate keys first.");
    }

    /** Checks the DESFire-side settings the phone credential reuses (AID, file, read key). */
    public void validateForPhone() {
        if (isZero(readKey)) throw new IllegalArgumentException("Generate and save DESFire keys first (the phone credential uses the DESFire read key)");
        if (aid <= 0 || aid >= 0xFFFFFF) throw new IllegalArgumentException("Invalid AID");
        if (diversify) throw new IllegalArgumentException("Turn off AV2 diversification: phones present a random UID");
    }

    public String ictMobileConfig(boolean dataLayer, boolean includeKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("ICT config - phone (NFC) credential\n");
        sb.append("===================================\n");
        sb.append("Adds to your DESFire card config; card slots stay as they are.\n\n");
        sb.append("1) Hex TLV - read key (same as DESFire cards)\n");
        sb.append("   ").append(includeKey ? "0311" + Hex.encode(readKey) : "0311<read key hidden>").append(String.format("%02X%n", ictKeyslot));
        if (dataLayer) {
            sb.append("   Hex TLV - AES-256 data key\n");
            sb.append("   ").append(includeKey ? "0321" + Hex.encode(mobileDataKey) : "0321<data key hidden>").append(String.format("%02X%n", ictDataKeyslot));
        }
        sb.append("\n2) Access Credentials\n");
        sb.append(String.format("   Slot             : %d%n", ictMobileCredentialSlot));
        sb.append("   Credential Type  : ISO7816 (NFC)\n");
        sb.append(String.format("   App ID           : %06X%n", aid));
        sb.append(String.format("   AES Keyslot      : %d%n", ictKeyslot));
        sb.append(String.format("   File Number      : %d%n%n", fileNo));
        sb.append("3) Custom Card Format Slots\n");
        sb.append(String.format("   Slot %d: %s = %s (already set for cards)%n", ictFormatSlot, ictFormatHex(), format.ictFormatString()));
        if (dataLayer) sb.append("   If the reader counts the IV block, try a format that skips 128 bits first.\n");
        sb.append("\n4) Card Linkages\n");
        sb.append(String.format("   Linkage Slot     : %d%n", ictMobileLinkageSlot));
        sb.append(dataLayer ? "   Flags            : AES 256 Decrypt CBC + AES IV in first block\n" : "   Flags            : none\n");
        sb.append(String.format("   Keyslot          : %d%n", dataLayer ? ictDataKeyslot : ictKeyslot));
        sb.append(String.format("   Access Cred Slot : %d%n", ictMobileCredentialSlot));
        sb.append(String.format("   Format Slot      : %d%n%n", ictFormatSlot));
        sb.append("Experimental: ICT doesn't publish the AID its readers SELECT on phones.\n");
        sb.append("Use the Phone tab log on the first tap to see what the reader sends.\n");
        return sb.toString();
    }

    public static boolean isZeroKey(byte[] k) { return isZero(k); }

    static boolean isZero(byte[] k) {
        for (byte b : k) if (b != 0) return false;
        return true;
    }

    // ICT reader slots (from the ICT Card Reader Configuration Guide custom credential example)
    public int ictKeyslot = 2;          // 0 and 1 reserved; 2-4 available
    public int ictCredentialSlot = 7;   // 5-8 available
    public int ictFormatSlot = 6;
    public int ictLinkageSlot = 6;

    /** The key the reader needs: DESFire AES read key, or Classic Key A. */
    public byte[] readerKey() { return cardType == CardType.CLASSIC ? classicKeyA : readKey; }

    /** ICT Keyslot hex TLV: 03 <len> <key> <keyslot>.  DESFire: 03 11 <16 bytes> <slot>; Classic: 03 07 <6 bytes> <slot>. */
    public String ictKeyslotTlv() {
        byte[] k = readerKey();
        return String.format("03%02X", k.length + 1) + Hex.encode(k) + String.format("%02X", ictKeyslot);
    }

    public String ictFormatHex() {
        return Hex.encode(format.ictFormatString().getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    /** Step-by-step settings for the Protege Config App. */
    public String ictConfig(boolean includeKey) {
        boolean classic = cardType == CardType.CLASSIC;
        byte[] k = readerKey();
        StringBuilder sb = new StringBuilder();
        sb.append("ICT reader config (Protege Config App)\n");
        sb.append("======================================\n\n");
        sb.append(classic ? "1) Hex TLV - load the MIFARE Classic Key A\n" : "1) Hex TLV - load the DESFire read key\n");
        String hidden = String.format("03%02X", k.length + 1) + "<key hidden>" + String.format("%02X", ictKeyslot);
        sb.append("   ").append(includeKey ? ictKeyslotTlv() : hidden).append("\n");
        sb.append(String.format("   (type 03, length %02X, %s, keyslot %d)%n%n", k.length + 1,
                classic ? "6-byte Classic Key A" : "AES-128 read key", ictKeyslot));
        sb.append("2) Access Credentials\n");
        sb.append(String.format("   Slot             : %d%n", ictCredentialSlot));
        if (classic) {
            sb.append("   Credential Type  : Mifare Classic\n");
            sb.append(String.format("   Block            : %d   (sector %d, first block)%n", classicBlock(), classicSector));
            sb.append("   Key Type         : A\n");
            sb.append(String.format("   Keyslot          : %d%n", ictKeyslot));
            sb.append("   Flags            : none (no Diversify Key)\n\n");
        } else {
            sb.append("   Credential Type  : Mifare DESFire\n");
            sb.append(String.format("   App ID           : %06X%n", aid));
            sb.append(String.format("   AES Keyslot      : %d%n", ictKeyslot));
            sb.append(String.format("   File Number      : %d%n", fileNo));
            sb.append(String.format("   Key Number       : %d%n", KEY_READ));
            sb.append(String.format("   Diversification  : %s%n%n", diversify ? "AV2 Diversification" : "No diversification"));
        }
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
        if (!classic) sb.append("6) tSec readers only, for EV2/EV3 cards - Hex TLV: 180106 (ISO14443 gain 6)\n");
        sb.append("\nApply within 2 minutes of power-cycling the reader.\n");
        if (classic) {
            sb.append(String.format("Card data: %s, big-endian, from byte 0 of block %d.%n", format.label, classicBlock()));
            sb.append("Note: MIFARE Classic (Crypto1) can be cloned with cheap tools. Use DESFire where security matters.\n");
        } else {
            sb.append(String.format("Card data: %s, big-endian, from byte 0. Comm mode: %s.%n", format.label,
                    comm == DesfireSession.Comm.ENC ? "encrypted" : comm == DesfireSession.Comm.MAC ? "MAC" : "plain"));
        }
        return sb.toString();
    }
}
