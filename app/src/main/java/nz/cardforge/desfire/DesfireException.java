package nz.cardforge.desfire;

public class DesfireException extends Exception {
    public final int status;

    public DesfireException(int status, String context) {
        super(context + ": " + describe(status) + String.format(" (0x%02X)", status));
        this.status = status;
    }

    public DesfireException(String message) {
        super(message);
        this.status = -1;
    }

    public boolean isAuthFailure() {
        return status == 0xAE || status == 0x9D || status == 0x40;
    }

    public static String describe(int s) {
        switch (s) {
            case 0x0C: return "No changes";
            case 0x0E: return "Out of EEPROM";
            case 0x1C: return "Illegal command";
            case 0x1E: return "Integrity error (CRC/MAC)";
            case 0x40: return "No such key";
            case 0x7E: return "Length error";
            case 0x9D: return "Permission denied";
            case 0x9E: return "Parameter error";
            case 0xA0: return "Application not found";
            case 0xAE: return "Authentication error (wrong key)";
            case 0xAF: return "Additional frame";
            case 0xBE: return "Boundary error";
            case 0xCA: return "Command aborted";
            case 0xDE: return "Duplicate (already exists)";
            case 0xEE: return "EEPROM error";
            case 0xF0: return "File not found";
            default: return "Error";
        }
    }
}
