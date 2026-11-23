package nz.cardforge;

import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;

import java.security.SecureRandom;

import nz.cardforge.desfire.CardProfile;
import nz.cardforge.desfire.Credential;
import nz.cardforge.desfire.DesfireEmulator;
import nz.cardforge.desfire.Hex;

/** Host Card Emulation: the phone answers the ICT reader as a DESFire card holding this phone's credential. */
public class PhoneCredentialService extends HostApduService {
    static final String[] DEFAULT_AIDS = {"F0434652474501", "D2760000850100", "D2760000850101"};

    private static final byte[] SW_NOT_FOUND = {0x6A, (byte) 0x82};
    private static final byte[] SW_ERROR = {0x6F, 0x00};

    private DesfireEmulator emu;
    private boolean disabledLogged;

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        byte[] resp;
        try {
            if (emu == null) emu = build();
            resp = emu == null ? SW_NOT_FOUND : emu.process(apdu);
        } catch (Exception e) {
            ApduLog.add("!  " + e.getMessage());
            resp = SW_ERROR;
        }
        ApduLog.add("R→P " + Hex.encode(apdu));
        ApduLog.add("P→R " + Hex.encode(resp));
        return resp;
    }

    @Override
    public void onDeactivated(int reason) {
        emu = null;
        disabledLogged = false;
        ApduLog.add("--- reader session ended (" + (reason == DEACTIVATION_LINK_LOSS ? "phone moved away" : "reader deselected") + ")");
    }

    private DesfireEmulator build() throws Exception {
        SharedPreferences st = getSharedPreferences("cardforge_state", MODE_PRIVATE);
        if (!st.getBoolean("phoneEnabled", false)) {
            if (!disabledLogged) ApduLog.add("--- reader selected us, but the phone credential is OFF");
            disabledLogged = true;
            return null;
        }
        CardProfile p = new ProfileStore(this).load();
        if (p == null) throw new IllegalStateException("No keys saved yet");
        p.validateForPhone();
        Credential c = new Credential(p.format, st.getLong("phoneSite", 1), st.getLong("phoneCard", 1));
        String uidHex = st.getString("phoneUid", null);
        if (uidHex == null) {
            byte[] u = new byte[7];
            new SecureRandom().nextBytes(u);
            u[0] = 0x08; // random-ID style first byte
            uidHex = Hex.encode(u);
            st.edit().putString("phoneUid", uidHex).apply();
        }
        boolean layer = st.getBoolean("phoneDataLayer", false);
        ApduLog.add("--- reader session started: presenting " + c + (layer ? " +AES-256 layer" : ""));
        return new DesfireEmulator(p, DesfireEmulator.mobileFile(p, c, layer, new SecureRandom()), Hex.decode(uidHex));
    }
}
