package nz.cardforge;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.json.JSONException;
import org.json.JSONObject;

import nz.cardforge.desfire.CardProfile;
import nz.cardforge.desfire.Credential;
import nz.cardforge.desfire.DesfireSession;
import nz.cardforge.desfire.Hex;

/** Stores the key profile encrypted with a non-exportable Android Keystore AES-GCM key. */
final class ProfileStore {
    private static final String ALIAS = "cardforge_profile_wrap";
    private static final String PREF = "profile_enc";
    private final SharedPreferences prefs;

    ProfileStore(Context ctx) {
        prefs = ctx.getSharedPreferences("cardforge_secure", Context.MODE_PRIVATE);
    }

    private SecretKey wrapKey() throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        if (!ks.containsAlias(ALIAS)) {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build());
            return kg.generateKey();
        }
        return (SecretKey) ks.getKey(ALIAS, null);
    }

    void save(CardProfile p) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, wrapKey());
        byte[] ct = c.doFinal(toJson(p).getBytes(StandardCharsets.UTF_8));
        byte[] blob = Hex.concat(c.getIV(), ct);
        prefs.edit().putString(PREF, Base64.encodeToString(blob, Base64.NO_WRAP)).apply();
    }

    CardProfile load() throws Exception {
        String s = prefs.getString(PREF, null);
        if (s == null) return null;
        byte[] blob = Base64.decode(s, Base64.NO_WRAP);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, wrapKey(), new GCMParameterSpec(128, Arrays.copyOf(blob, 12)));
        byte[] pt = c.doFinal(Arrays.copyOfRange(blob, 12, blob.length));
        return fromJson(new String(pt, StandardCharsets.UTF_8));
    }

    static String toJson(CardProfile p) throws JSONException {
        JSONObject o = new JSONObject();
        o.put("type", "cardforge-profile");
        o.put("v", 1);
        o.put("aid", String.format("%06X", p.aid));
        o.put("fileNo", p.fileNo);
        o.put("fileSize", p.fileSize);
        o.put("comm", p.comm.code);
        o.put("format", p.format.id);
        o.put("piccMasterKey", Hex.encode(p.piccMasterKey));
        o.put("appMasterKey", Hex.encode(p.appMasterKey));
        o.put("readKey", Hex.encode(p.readKey));
        o.put("writeKey", Hex.encode(p.writeKey));
        o.put("diversify", p.diversify);
        o.put("systemId", Hex.encode(p.systemId));
        o.put("lockPicc", p.lockPicc);
        o.put("keyVersion", p.keyVersion);
        o.put("ictKeyslot", p.ictKeyslot);
        o.put("ictCredentialSlot", p.ictCredentialSlot);
        o.put("ictFormatSlot", p.ictFormatSlot);
        o.put("ictLinkageSlot", p.ictLinkageSlot);
        o.put("cardType", p.cardType.name());
        o.put("classicSector", p.classicSector);
        o.put("classicKeyA", Hex.encode(p.classicKeyA));
        o.put("classicKeyB", Hex.encode(p.classicKeyB));
        return o.toString(2);
    }

    static CardProfile fromJson(String json) throws JSONException {
        JSONObject o = new JSONObject(json.trim());
        if (!"cardforge-profile".equals(o.optString("type"))) throw new JSONException("Not a CardForge profile");
        CardProfile p = new CardProfile();
        p.aid = Integer.parseInt(o.getString("aid"), 16);
        p.fileNo = o.optInt("fileNo", 1);
        p.fileSize = o.optInt("fileSize", 32);
        p.comm = DesfireSession.Comm.fromCode(o.optInt("comm", 3));
        p.format = Credential.Format.fromId(o.optInt("format", Credential.Format.W34.id));
        p.piccMasterKey = Hex.decode(o.getString("piccMasterKey"));
        p.appMasterKey = Hex.decode(o.getString("appMasterKey"));
        p.readKey = Hex.decode(o.getString("readKey"));
        p.writeKey = Hex.decode(o.getString("writeKey"));
        p.diversify = o.optBoolean("diversify", false);
        p.systemId = Hex.decode(o.optString("systemId", ""));
        p.lockPicc = o.optBoolean("lockPicc", false);
        p.keyVersion = o.optInt("keyVersion", 1);
        p.ictKeyslot = o.optInt("ictKeyslot", 2);
        p.ictCredentialSlot = o.optInt("ictCredentialSlot", 7);
        p.ictFormatSlot = o.optInt("ictFormatSlot", 6);
        p.ictLinkageSlot = o.optInt("ictLinkageSlot", 6);
        p.cardType = CardProfile.CardType.valueOf(o.optString("cardType", "DESFIRE"));
        p.classicSector = o.optInt("classicSector", 1);
        if (o.has("classicKeyA") && o.has("classicKeyB")) {
            p.classicKeyA = Hex.decode(o.getString("classicKeyA"));
            p.classicKeyB = Hex.decode(o.getString("classicKeyB"));
        } else {
            p.generateClassicKeys(new java.security.SecureRandom()); // profiles saved before Classic support
        }
        p.validate();
        return p;
    }
}
