package nz.cardforge;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipDescription;
import android.content.ClipboardManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.cardemulation.CardEmulation;
import android.content.pm.PackageManager;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.nfc.tech.MifareClassic;
import android.nfc.tech.TagTechnology;
import android.os.Build;
import android.os.Bundle;
import android.os.PersistableBundle;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import nz.cardforge.desfire.CardEncoder;
import nz.cardforge.desfire.CardProfile;
import nz.cardforge.desfire.ClassicEncoder;
import nz.cardforge.desfire.CredentialEncoder;
import nz.cardforge.desfire.Credential;
import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.DesfireSession;
import nz.cardforge.desfire.Hex;

public class MainActivity extends Activity implements NfcAdapter.ReaderCallback {

    private enum Mode { ENCODE, VERIFY, WIPE, PHONE, KEYS }

    private static final int GREEN = Color.rgb(0x1B, 0x7F, 0x3A), RED = Color.rgb(0xC6, 0x28, 0x28), GREY = Color.rgb(0x55, 0x55, 0x55);
    private static final DesfireSession.Comm[] COMMS = {DesfireSession.Comm.ENC, DesfireSession.Comm.MAC, DesfireSession.Comm.PLAIN};

    private volatile Mode mode = Mode.ENCODE;
    private volatile CardProfile profile;
    private NfcAdapter nfc;
    private ProfileStore store;
    private SharedPreferences state;
    private final AtomicBoolean busy = new AtomicBoolean(false);

    private LinearLayout encodePanel, verifyPanel, wipePanel, keysPanel;
    private final Button[] tabs = new Button[5];
    private LinearLayout phonePanel;
    private CheckBox phoneEnabled, phoneLayer;
    private EditText phoneSiteIn, phoneCardIn, aidsIn;
    private TextView phoneLog;
    private boolean resumed;
    private TextView status, logView, profileSummary;
    private EditText siteIn, cardIn;
    private CheckBox autoInc, overwrite, wipeArmed;
    private EditText aidIn, keyslotIn, sysIdIn, piccIn, masterIn, readIn, writeIn;
    private Spinner formatSpin, commSpin, typeSpin;
    private EditText sectorIn, classicAIn, classicBIn;
    private View[] desfireViews, classicViews;
    private CheckBox divBox, lockBox, revealBox;

    // ------------------------------------------------------------------ lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        nfc = NfcAdapter.getDefaultAdapter(this);
        store = new ProfileStore(this);
        state = getSharedPreferences("cardforge_state", MODE_PRIVATE);
        try {
            profile = store.load();
        } catch (Exception e) {
            profile = null;
            Toast.makeText(this, "Couldn't unlock saved keys: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
        buildUi();
        if (profile == null) {
            profile = new CardProfile();
            fillKeyFields();
            setMode(Mode.KEYS);
            setStatus("First run: generate keys, then Save.", GREY);
        } else {
            fillKeyFields();
            setMode(Mode.ENCODE);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        resumed = true;
        ApduLog.setListener(() -> runOnUiThread(() -> phoneLog.setText(ApduLog.dump())));
        phoneLog.setText(ApduLog.dump());
        if (nfc == null) {
            setStatus("This phone has no NFC.", RED);
            return;
        }
        if (!nfc.isEnabled()) {
            setStatus("NFC is off - turn it on in Settings.", RED);
            return;
        }
        updateNfcRole();
    }

    @Override
    protected void onPause() {
        super.onPause();
        resumed = false;
        ApduLog.setListener(null);
        if (nfc != null) {
            nfc.disableReaderMode(this);
            CardEmulation ce = cardEmulation();
            if (ce != null) ce.unsetPreferredService(this);
        }
    }

    private boolean hasHce() {
        return getPackageManager().hasSystemFeature(PackageManager.FEATURE_NFC_HOST_CARD_EMULATION);
    }

    private CardEmulation cardEmulation() {
        if (nfc == null || !hasHce()) return null;
        try {
            return CardEmulation.getInstance(nfc);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private ComponentName hceComponent() { return new ComponentName(this, PhoneCredentialService.class); }

    /** Reader mode (encode/verify/wipe) and card emulation (Phone tab) can't run at the same time. */
    private void updateNfcRole() {
        if (nfc == null || !resumed || !nfc.isEnabled()) return;
        CardEmulation ce = cardEmulation();
        if (mode == Mode.PHONE) {
            nfc.disableReaderMode(this);
            if (ce != null) ce.setPreferredService(this, hceComponent());
        } else {
            if (ce != null) ce.unsetPreferredService(this);
            Bundle opts = new Bundle();
            opts.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000);
            nfc.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, opts);
        }
    }

    // ------------------------------------------------------------------ NFC

    @Override
    public void onTagDiscovered(Tag tag) {
        if (!busy.compareAndSet(false, true)) return;
        TagTechnology conn = null;
        try {
            final Mode m = mode;
            final CardProfile p = profile;
            final boolean classic = p.cardType == CardProfile.CardType.CLASSIC;
            if (m == Mode.KEYS || m == Mode.PHONE) {
                ui(() -> setStatus("Switch to Encode, Verify or Wipe to use a card.", GREY));
                return;
            }
            ui(() -> {
                logView.setText("");
                setStatus("Working... keep the card still", GREY);
            });

            // Snapshot form values on the UI thread.
            final Object[] form = onUi(() -> new Object[] {
                    siteIn.getText().toString().trim(), cardIn.getText().toString().trim(),
                    overwrite.isChecked(), autoInc.isChecked(), wipeArmed.isChecked()});

            if (m == Mode.WIPE && !(Boolean) form[4]) {
                ui(() -> setStatus("Tick \"Armed\" first, then tap the card to wipe it.", RED));
                return;
            }
            Credential cred = null;
            if (m == Mode.ENCODE) {
                cred = new Credential(p.format, Long.parseLong((String) form[0]), Long.parseLong((String) form[1]));
            }

            CredentialEncoder enc;
            if (classic) {
                MifareClassic mfc = MifareClassic.get(tag);
                if (mfc == null) {
                    boolean desfire = IsoDep.get(tag) != null;
                    ui(() -> setStatus(desfire
                            ? "That's a DESFire card - switch Card type to DESFire in Keys."
                            : "Can't open as MIFARE Classic. Either it's not a Classic card, or this phone's NFC chip doesn't support Classic (many Samsung/Pixel phones don't).", RED));
                    return;
                }
                conn = mfc;
                mfc.connect();
                mfc.setTimeout(1000);
                enc = new ClassicEncoder(new AndroidClassic(mfc), p, tag.getId(), this::logLine);
            } else {
                IsoDep iso = IsoDep.get(tag);
                if (iso == null) {
                    ui(() -> setStatus("Not a DESFire card (no ISO-DEP). If it's MIFARE Classic, change Card type in Keys.", RED));
                    return;
                }
                conn = iso;
                iso.connect();
                iso.setTimeout(3000);
                DesfireSession session = new DesfireSession(iso::transceive);
                enc = new CardEncoder(session, p, tag.getId(), this::logLine);
            }

            switch (m) {
                case ENCODE: {
                    Credential done = enc.encode(cred, (Boolean) form[2]);
                    long next = done.card + 1;
                    state.edit().putString("site", (String) form[0]).apply();
                    if ((Boolean) form[3]) state.edit().putLong("nextCard", next).apply();
                    ui(() -> {
                        setStatus("Encoded ✔  " + done, GREEN);
                        if ((Boolean) form[3] && next <= p.format.maxCard()) cardIn.setText(String.valueOf(next));
                    });
                    break;
                }
                case VERIFY: {
                    Credential c = enc.verify();
                    ui(() -> setStatus("Valid ✔  Site " + c.site + "  /  Card " + c.card + "  (" + c.format.name() + ")", GREEN));
                    break;
                }
                case WIPE: {
                    enc.wipe();
                    ui(() -> {
                        wipeArmed.setChecked(false);
                        setStatus("Wiped ✔  Card is back to factory state.", GREEN);
                    });
                    break;
                }
                default:
                    break;
            }
        } catch (NumberFormatException e) {
            ui(() -> setStatus("Enter a numeric site code and card ID.", RED));
        } catch (TagLostException e) {
            ui(() -> setStatus("Card moved away mid-write. Hold it still and tap again (tick Overwrite if needed).", RED));
        } catch (IOException e) {
            ui(() -> setStatus("Communication error: " + e.getMessage(), RED));
        } catch (DesfireException | RuntimeException e) {
            ui(() -> setStatus(e.getMessage(), RED));
        } finally {
            try {
                if (conn != null) conn.close();
            } catch (IOException ignored) {
            }
            busy.set(false);
        }
    }

    private void logLine(String s) {
        ui(() -> logView.append("• " + s + "\n"));
    }

    private void ui(Runnable r) { runOnUiThread(r); }

    private <T> T onUi(Callable<T> c) {
        AtomicReference<T> ref = new AtomicReference<>();
        CountDownLatch latch = new CountDownLatch(1);
        runOnUiThread(() -> {
            try {
                ref.set(c.call());
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                latch.countDown();
            }
        });
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return ref.get();
    }

    // ------------------------------------------------------------------ UI

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(24));
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("CardForge · DESFire encoder");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        profileSummary = new TextView(this);
        profileSummary.setTextColor(GREY);
        profileSummary.setTextSize(12);
        root.addView(profileSummary);

        LinearLayout tabRow = new LinearLayout(this);
        tabRow.setOrientation(LinearLayout.HORIZONTAL);
        tabRow.setPadding(0, dp(12), 0, dp(8));
        String[] names = {"Encode", "Verify", "Wipe", "Phone", "Keys"};
        for (int i = 0; i < names.length; i++) {
            Button b = new Button(this);
            b.setText(names[i]);
            b.setAllCaps(false);
            final Mode m = Mode.values()[i];
            b.setOnClickListener(v -> setMode(m));
            tabRow.addView(b, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            tabs[i] = b;
        }
        root.addView(tabRow);

        status = new TextView(this);
        status.setTextSize(17);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setPadding(0, dp(8), 0, dp(8));
        root.addView(status);

        // Encode
        encodePanel = panel(root);
        hint(encodePanel, "Fill in the credential, then hold a blank card (type set in Keys) to the back of the phone.");
        siteIn = field(encodePanel, "Site code", InputType.TYPE_CLASS_NUMBER);
        cardIn = field(encodePanel, "Card ID", InputType.TYPE_CLASS_NUMBER);
        siteIn.setText(state.getString("site", "1"));
        cardIn.setText(String.valueOf(state.getLong("nextCard", 1)));
        autoInc = check(encodePanel, "Auto-increment card ID after each card", true);
        overwrite = check(encodePanel, "Overwrite if the card is already encoded", false);

        // Verify
        verifyPanel = panel(root);
        hint(verifyPanel, "Hold a card to the phone. It is read exactly like the ICT reader does: select app, authenticate with the read key (key 1), read the file.");

        // Wipe
        wipePanel = panel(root);
        hint(wipePanel, "Deletes the CardForge application and restores the factory card master key so the card can be re-used.");
        wipeArmed = check(wipePanel, "Armed (wipe the next card tapped)", false);

        // Keys
        // Phone credential (HCE)
        phonePanel = panel(root);
        hint(phonePanel, "Turns this phone into a DESFire credential for the ICT reader. Stay on this tab, keep the screen on and unlocked, and hold the phone to the reader. Uses the DESFire AID and read key from Keys.");
        if (!hasHce()) hint(phonePanel, "⚠ This phone doesn't support NFC card emulation (HCE).");
        phoneEnabled = check(phonePanel, "Phone credential ON", state.getBoolean("phoneEnabled", false));
        phoneEnabled.setOnCheckedChangeListener((b, on) -> state.edit().putBoolean("phoneEnabled", on).apply());
        phoneSiteIn = field(phonePanel, "Phone credential site code", InputType.TYPE_CLASS_NUMBER);
        phoneCardIn = field(phonePanel, "Phone credential card ID", InputType.TYPE_CLASS_NUMBER);
        phoneSiteIn.setText(String.valueOf(state.getLong("phoneSite", 1)));
        phoneCardIn.setText(String.valueOf(state.getLong("phoneCard", 1)));
        phoneLayer = check(phonePanel, "AES-256 data layer (ICT mobile style, experimental)", state.getBoolean("phoneDataLayer", false));
        phoneLayer.setOnCheckedChangeListener((b, on) -> state.edit().putBoolean("phoneDataLayer", on).apply());
        button(phonePanel, "Save phone credential", v -> savePhone());
        button(phonePanel, "ICT config for phone credentials", v -> showPhoneConfig());
        aidsIn = field(phonePanel, "Extra AIDs to answer (hex, comma separated, 5-16 bytes)", InputType.TYPE_CLASS_TEXT);
        aidsIn.setText(state.getString("extraAids", ""));
        button(phonePanel, "Apply AIDs", v -> applyAids());
        TextView lt = new TextView(this);
        lt.setText("Reader traffic (R→P reader to phone, P→R phone to reader)");
        lt.setTypeface(Typeface.DEFAULT_BOLD);
        lt.setPadding(0, dp(12), 0, dp(4));
        phonePanel.addView(lt);
        button(phonePanel, "Copy log", v -> copyPlain("Reader log", ApduLog.dump()));
        button(phonePanel, "Clear log", v -> ApduLog.clear());
        phoneLog = new TextView(this);
        phoneLog.setTypeface(Typeface.MONOSPACE);
        phoneLog.setTextSize(11);
        phoneLog.setTextIsSelectable(true);
        phonePanel.addView(phoneLog);

        keysPanel = panel(root);
        hint(keysPanel, "Site settings. These must match the ICT reader config. Changing keys or AID after cards are issued makes those cards unreadable.");
        typeSpin = spinner(keysPanel, "Card type", new String[] {"MIFARE DESFire EV1/EV2/EV3 (secure)", "MIFARE Classic 1K/4K (legacy)"});
        aidIn = field(keysPanel, "DESFire application ID (6 hex)", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS);
        formatSpin = spinner(keysPanel, "Credential format", new String[] {
                Credential.Format.W26.label, Credential.Format.W34.label, Credential.Format.RAW48.label});
        commSpin = spinner(keysPanel, "File communication", new String[] {"Encrypted (recommended)", "MAC", "Plain"});
        keyslotIn = field(keysPanel, "ICT reader keyslot (2-4)", InputType.TYPE_CLASS_NUMBER);
        divBox = check(keysPanel, "AV2 key diversification per card UID (test with your reader first)", false);
        sysIdIn = field(keysPanel, "AV2 system ID hex (normally blank for ICT)", InputType.TYPE_CLASS_TEXT);
        lockBox = check(keysPanel, "Lock card master key with custom key (Wipe can undo)", false);
        revealBox = check(keysPanel, "Show keys", false);
        revealBox.setOnCheckedChangeListener((b, on) -> setKeysVisible(on));
        readIn = field(keysPanel, "Read key (key 1) - goes into the reader", 0);
        writeIn = field(keysPanel, "Write key (key 2) - phone only", 0);
        masterIn = field(keysPanel, "App master key (key 0) - phone only", 0);
        piccIn = field(keysPanel, "Card master key - phone only", 0);
        sectorIn = field(keysPanel, "Classic sector (1-15) - credential goes in its first block", InputType.TYPE_CLASS_NUMBER);
        classicAIn = field(keysPanel, "Classic Key A (12 hex) - read key, goes into the reader", 0);
        classicBIn = field(keysPanel, "Classic Key B (12 hex) - write key, phone only", 0);
        desfireViews = new View[] {box(aidIn), box(commSpin), divBox, box(sysIdIn), lockBox, box(readIn), box(writeIn), box(masterIn), box(piccIn)};
        classicViews = new View[] {box(sectorIn), box(classicAIn), box(classicBIn)};
        typeSpin.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View view, int pos, long id) { showTypeFields(); }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) { }
        });
        setKeysVisible(false);
        button(keysPanel, "Generate new random keys", v -> confirmGenerate());
        button(keysPanel, "Save", v -> saveKeys());
        button(keysPanel, "ICT reader config + keyslot TLV", v -> showReaderConfig());
        button(keysPanel, "Export profile (for a 2nd phone)", v -> exportProfile());
        button(keysPanel, "Import profile", v -> importProfile());

        TextView logTitle = new TextView(this);
        logTitle.setText("Log");
        logTitle.setTypeface(Typeface.DEFAULT_BOLD);
        logTitle.setPadding(0, dp(16), 0, dp(4));
        root.addView(logTitle);
        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(12);
        root.addView(logView);

        setContentView(scroll);
    }

    private LinearLayout panel(LinearLayout root) {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        root.addView(p);
        return p;
    }

    private void hint(LinearLayout parent, String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(GREY);
        t.setPadding(0, 0, 0, dp(8));
        parent.addView(t);
    }

    private EditText field(LinearLayout parent, String label, int inputType) {
        LinearLayout c = panel(parent);
        TextView l = new TextView(this);
        l.setText(label);
        l.setPadding(0, dp(8), 0, 0);
        c.addView(l);
        EditText e = new EditText(this);
        if (inputType != 0) e.setInputType(inputType);
        e.setSingleLine(true);
        c.addView(e);
        return e;
    }

    /** The labelled container a field or spinner lives in. */
    private static View box(View v) { return (View) v.getParent(); }

    private boolean classicSelected() { return typeSpin.getSelectedItemPosition() == 1; }

    private void showTypeFields() {
        boolean classic = classicSelected();
        for (View v : desfireViews) v.setVisibility(classic ? View.GONE : View.VISIBLE);
        for (View v : classicViews) v.setVisibility(classic ? View.VISIBLE : View.GONE);
    }

    private CheckBox check(LinearLayout parent, String text, boolean checked) {
        CheckBox c = new CheckBox(this);
        c.setText(text);
        c.setChecked(checked);
        parent.addView(c);
        return c;
    }

    private Spinner spinner(LinearLayout parent, String label, String[] items) {
        LinearLayout c = panel(parent);
        TextView l = new TextView(this);
        l.setText(label);
        l.setPadding(0, dp(8), 0, 0);
        c.addView(l);
        Spinner s = new Spinner(this);
        ArrayAdapter<String> a = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, items);
        a.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        s.setAdapter(a);
        c.addView(s);
        return s;
    }

    private void button(LinearLayout parent, String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        parent.addView(b);
    }

    private void setKeysVisible(boolean visible) {
        int type = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                | (visible ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD : InputType.TYPE_TEXT_VARIATION_PASSWORD);
        for (EditText e : new EditText[] {readIn, writeIn, masterIn, piccIn, classicAIn, classicBIn}) {
            e.setInputType(type);
            e.setTypeface(Typeface.MONOSPACE);
        }
    }

    private void setMode(Mode m) {
        mode = m;
        encodePanel.setVisibility(m == Mode.ENCODE ? View.VISIBLE : View.GONE);
        verifyPanel.setVisibility(m == Mode.VERIFY ? View.VISIBLE : View.GONE);
        wipePanel.setVisibility(m == Mode.WIPE ? View.VISIBLE : View.GONE);
        keysPanel.setVisibility(m == Mode.KEYS ? View.VISIBLE : View.GONE);
        phonePanel.setVisibility(m == Mode.PHONE ? View.VISIBLE : View.GONE);
        for (int i = 0; i < tabs.length; i++) tabs[i].setEnabled(Mode.values()[i] != m);
        if (m == Mode.WIPE) wipeArmed.setChecked(false);
        switch (m) {
            case ENCODE: setStatus("Ready to encode - tap a card", GREY); break;
            case VERIFY: setStatus("Ready to verify - tap a card", GREY); break;
            case WIPE: setStatus("Tick Armed, then tap a card", GREY); break;
            case PHONE:
                setStatus(state.getBoolean("phoneEnabled", false) ? "Phone is acting as a card - hold it to the reader" : "Tick \"Phone credential ON\" to present this phone", GREY);
                break;
            default: setStatus("Edit site settings, then Save", GREY);
        }
        updateNfcRole();
    }

    private void savePhone() {
        try {
            long site = Long.parseLong(phoneSiteIn.getText().toString().trim());
            long card = Long.parseLong(phoneCardIn.getText().toString().trim());
            new Credential(profile.format, site, card); // range check for the current format
            profile.validateForPhone();
            state.edit().putLong("phoneSite", site).putLong("phoneCard", card).apply();
            setStatus("Phone credential saved: site " + site + " / card " + card, GREEN);
        } catch (NumberFormatException e) {
            setStatus("Enter a numeric site code and card ID.", RED);
        } catch (RuntimeException e) {
            setStatus(e.getMessage(), RED);
        }
    }

    private void applyAids() {
        CardEmulation ce = cardEmulation();
        if (ce == null) {
            setStatus("This phone doesn't support NFC card emulation.", RED);
            return;
        }
        List<String> aids = new ArrayList<>();
        for (String a : PhoneCredentialService.DEFAULT_AIDS) aids.add(a);
        String raw = aidsIn.getText().toString().trim();
        try {
            for (String part : raw.split("[,\\s]+")) {
                if (part.isEmpty()) continue;
                String a = part.toUpperCase(java.util.Locale.US);
                byte[] b = Hex.decode(a);
                if (b.length < 5 || b.length > 16) throw new IllegalArgumentException("AID " + a + " must be 5-16 bytes");
                if (!aids.contains(a)) aids.add(a);
            }
            boolean ok = ce.registerAidsForService(hceComponent(), CardEmulation.CATEGORY_OTHER, aids);
            state.edit().putString("extraAids", raw).apply();
            setStatus(ok ? "Answering " + aids.size() + " AIDs" : "Android rejected the AID list", ok ? GREEN : RED);
        } catch (RuntimeException e) {
            setStatus(e.getMessage(), RED);
        }
    }

    private void showPhoneConfig() {
        CardProfile p = profile;
        try {
            p.validateForPhone();
        } catch (RuntimeException e) {
            setStatus(e.getMessage(), RED);
            return;
        }
        boolean layer = phoneLayer.isChecked();
        TextView t = new TextView(this);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(12);
        t.setTextIsSelectable(true);
        t.setPadding(dp(16), dp(8), dp(16), dp(8));
        t.setText(p.ictMobileConfig(layer, true));
        ScrollView sv = new ScrollView(this);
        sv.addView(t);
        new AlertDialog.Builder(this)
                .setTitle("ICT config - phone credential")
                .setView(sv)
                .setPositiveButton("Copy all", (d, w) -> copy("Phone reader config", p.ictMobileConfig(layer, true)))
                .setNegativeButton("Close", null)
                .show();
    }

    private void copyPlain(String label, String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText(label, text));
        Toast.makeText(this, label + " copied", Toast.LENGTH_SHORT).show();
    }

    private void setStatus(String text, int color) {
        status.setText(text);
        status.setTextColor(color);
    }

    private void fillKeyFields() {
        CardProfile p = profile;
        aidIn.setText(String.format("%06X", p.aid));
        formatSpin.setSelection(p.format.ordinal());
        int ci = 0;
        for (int i = 0; i < COMMS.length; i++) if (COMMS[i] == p.comm) ci = i;
        commSpin.setSelection(ci);
        keyslotIn.setText(String.valueOf(p.ictKeyslot));
        divBox.setChecked(p.diversify);
        sysIdIn.setText(Hex.encode(p.systemId));
        lockBox.setChecked(p.lockPicc);
        readIn.setText(Hex.encode(p.readKey));
        writeIn.setText(Hex.encode(p.writeKey));
        masterIn.setText(Hex.encode(p.appMasterKey));
        piccIn.setText(Hex.encode(p.piccMasterKey));
        boolean classic = p.cardType == CardProfile.CardType.CLASSIC;
        typeSpin.setSelection(classic ? 1 : 0);
        sectorIn.setText(String.valueOf(p.classicSector));
        classicAIn.setText(Hex.encode(p.classicKeyA));
        classicBIn.setText(Hex.encode(p.classicKeyB));
        showTypeFields();
        profileSummary.setText(classic
                ? String.format("MIFARE Classic · sector %d (block %d) · %s", p.classicSector, p.classicBlock(), p.format.name())
                : String.format("DESFire · AID %06X · %s · %s%s", p.aid, p.format.name(), p.comm.name(), p.diversify ? " · AV2" : ""));
    }

    private void confirmGenerate() {
        new AlertDialog.Builder(this)
                .setTitle(classicSelected() ? "Generate new Classic keys?" : "Generate new DESFire keys?")
                .setMessage("Only the keys for the selected card type change. Cards already encoded with the current keys will stop working, and the ICT reader must be re-programmed with the new read key.")
                .setPositiveButton("Generate", (d, w) -> {
                    CardProfile g = CardProfile.generate(new SecureRandom());
                    if (classicSelected()) {
                        classicAIn.setText(Hex.encode(g.classicKeyA));
                        classicBIn.setText(Hex.encode(g.classicKeyB));
                    } else {
                        readIn.setText(Hex.encode(g.readKey));
                        writeIn.setText(Hex.encode(g.writeKey));
                        masterIn.setText(Hex.encode(g.appMasterKey));
                        piccIn.setText(Hex.encode(g.piccMasterKey));
                    }
                    setStatus("New keys generated - tap Save.", GREY);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void saveKeys() {
        try {
            CardProfile p = new CardProfile();
            p.aid = Integer.parseInt(aidIn.getText().toString().trim(), 16);
            p.format = Credential.Format.values()[formatSpin.getSelectedItemPosition()];
            p.comm = COMMS[commSpin.getSelectedItemPosition()];
            p.ictKeyslot = Integer.parseInt(keyslotIn.getText().toString().trim());
            p.diversify = divBox.isChecked();
            p.systemId = Hex.decode(sysIdIn.getText().toString().trim());
            p.lockPicc = lockBox.isChecked();
            p.readKey = Hex.decode(readIn.getText().toString().trim());
            p.writeKey = Hex.decode(writeIn.getText().toString().trim());
            p.appMasterKey = Hex.decode(masterIn.getText().toString().trim());
            p.piccMasterKey = Hex.decode(piccIn.getText().toString().trim());
            p.cardType = classicSelected() ? CardProfile.CardType.CLASSIC : CardProfile.CardType.DESFIRE;
            p.classicSector = Integer.parseInt(sectorIn.getText().toString().trim());
            p.classicKeyA = Hex.decode(classicAIn.getText().toString().trim());
            p.classicKeyB = Hex.decode(classicBIn.getText().toString().trim());
            CardProfile old = profile;
            p.mobileDataKey = old.mobileDataKey.clone();
            if (CardProfile.isZeroKey(p.mobileDataKey)) new SecureRandom().nextBytes(p.mobileDataKey);
            p.ictCredentialSlot = old.ictCredentialSlot;
            p.ictFormatSlot = old.ictFormatSlot;
            p.ictLinkageSlot = old.ictLinkageSlot;
            p.validate();
            store.save(p);
            profile = p;
            fillKeyFields();
            setStatus("Saved ✔ (encrypted with the phone's keystore)", GREEN);
        } catch (Exception e) {
            setStatus("Not saved: " + e.getMessage(), RED);
        }
    }

    private void copy(String label, String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText(label, text);
        if (Build.VERSION.SDK_INT >= 33) {
            PersistableBundle extras = new PersistableBundle();
            extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true);
            clip.getDescription().setExtras(extras);
        }
        cm.setPrimaryClip(clip);
        Toast.makeText(this, label + " copied", Toast.LENGTH_SHORT).show();
    }

    private void showReaderConfig() {
        CardProfile p = profile;
        try {
            p.validate();
        } catch (RuntimeException e) {
            setStatus("Save valid keys first: " + e.getMessage(), RED);
            return;
        }
        TextView t = new TextView(this);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextSize(12);
        t.setTextIsSelectable(true);
        t.setPadding(dp(16), dp(8), dp(16), dp(8));
        t.setText(p.ictConfig(true));
        ScrollView sv = new ScrollView(this);
        sv.addView(t);
        new AlertDialog.Builder(this)
                .setTitle("ICT reader configuration")
                .setView(sv)
                .setPositiveButton("Copy keyslot TLV", (d, w) -> copy("Keyslot TLV", p.ictKeyslotTlv()))
                .setNeutralButton("Copy all", (d, w) -> copy("Reader config", p.ictConfig(true)))
                .setNegativeButton("Close", null)
                .show();
    }

    private void exportProfile() {
        new AlertDialog.Builder(this)
                .setTitle("Export all keys?")
                .setMessage("The export contains every key in plain text. Anyone with it can create or wipe your cards. Only send it somewhere private (e.g. your password manager).")
                .setPositiveButton("Export", (d, w) -> {
                    try {
                        Intent i = new Intent(Intent.ACTION_SEND);
                        i.setType("text/plain");
                        i.putExtra(Intent.EXTRA_TEXT, ProfileStore.toJson(profile));
                        startActivity(Intent.createChooser(i, "Export CardForge profile"));
                    } catch (Exception e) {
                        setStatus("Export failed: " + e.getMessage(), RED);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void importProfile() {
        EditText in = new EditText(this);
        in.setHint("Paste profile JSON");
        in.setMinLines(6);
        in.setGravity(Gravity.TOP);
        in.setTypeface(Typeface.MONOSPACE);
        new AlertDialog.Builder(this)
                .setTitle("Import profile")
                .setMessage("This replaces the keys on this phone.")
                .setView(in)
                .setPositiveButton("Import", (d, w) -> {
                    try {
                        CardProfile p = ProfileStore.fromJson(in.getText().toString());
                        store.save(p);
                        profile = p;
                        fillKeyFields();
                        setStatus("Profile imported ✔", GREEN);
                    } catch (Exception e) {
                        setStatus("Import failed: " + e.getMessage(), RED);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }
}
