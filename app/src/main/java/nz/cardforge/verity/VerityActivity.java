package nz.cardforge.verity;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.nfc.tech.NfcA;
import android.os.Bundle;
import android.text.InputType;
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

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.Hex;
import nz.cardforge.ntag.Ntag424Encoder;
import nz.cardforge.ntag.Ntag424Session;
import nz.cardforge.ntag.Ntag21xEncoder;

/**
 * Verity mode: staff encode NTAG 424 DNA product tags, check them, and wipe test tags.
 * Keys come from the Verity server one tag at a time and are wiped from memory after use.
 */
public class VerityActivity extends Activity implements NfcAdapter.ReaderCallback {

    private enum Mode { ENCODE, CHECK, RESET }

    private static final int GREEN = Color.rgb(0x11, 0x80, 0x5B), RED = Color.rgb(0xC6, 0x28, 0x28),
            ORANGE = Color.rgb(0xB4, 0x48, 0x0F), GREY = Color.rgb(0x55, 0x55, 0x55);

    private volatile Mode mode = Mode.ENCODE;
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private NfcAdapter nfc;
    private VerityApi api;

    private LinearLayout signInPanel, workPanel, resetPanel;
    private EditText emailIn, passwordIn;
    private TextView who, status, logView, modeHint;
    private Spinner batchSpin;
    private CheckBox resetArmed;
    private final Button[] tabs = new Button[3];
    private final List<String> batchIds = new ArrayList<>();
    private String lastTapUrl;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        nfc = NfcAdapter.getDefaultAdapter(this);
        api = new VerityApi(getSharedPreferences("verity", MODE_PRIVATE));
        buildUi();
        refreshSignIn();
        setMode(Mode.ENCODE);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfc == null) { setStatus("This phone has no NFC.", RED); return; }
        if (!nfc.isEnabled()) { setStatus("NFC is off. Turn it on in Settings.", RED); return; }
        Bundle opts = new Bundle();
        opts.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 1000);
        nfc.enableReaderMode(this, this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, opts);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfc != null) nfc.disableReaderMode(this);
    }

    // ------------------------------------------------------------------ NFC

    @Override
    public void onTagDiscovered(Tag tag) {
        if (!busy.compareAndSet(false, true)) return;
        IsoDep iso = null;
        Ntag424Encoder.TagKeys keys = null;
        try {
            if (!api.isSignedIn()) { ui(() -> setStatus("Sign in first.", RED)); return; }
            final Mode m = mode;
            byte[] id = tag.getId();
            if (id.length != 7) { ui(() -> setStatus("This isn't an NTAG 424 DNA or NTAG21x (UID isn't 7 bytes).", RED)); return; }
            String uid = Hex.encode(id);
            iso = IsoDep.get(tag);
            if (iso == null) {
                NfcA a = NfcA.get(tag);
                if (a == null) { ui(() -> setStatus("Unsupported tag. Use NTAG 424 DNA (or NTAG213/215/216 for testing).", RED)); return; }
                handleTestTag(a, uid, m);
                return;
            }
            iso.connect();
            iso.setTimeout(3000);
            Ntag424Encoder enc = new Ntag424Encoder(new Ntag424Session(iso::transceive));
            ui(() -> { logView.setText(""); setStatus("Working… keep the tag still", GREY); });
            log("Tag " + uid);

            switch (m) {
                case ENCODE: {
                    String batchId = onUiBatch();
                    if (batchId == null) { ui(() -> setStatus("Pick a batch first (tap Refresh batches).", RED)); return; }
                    log("Fetching this tag's keys from Verity");
                    JSONObject r = api.encoder(new JSONObject().put("action", "tag_keys").put("batch_id", batchId).put("uid", uid));
                    keys = keysFrom(r.getJSONObject("keys"));
                    String template = r.getString("url");
                    log("Writing URL, SUN settings and 5 AES keys");
                    enc.encode(keys, template);
                    api.encoder(new JSONObject().put("action", "register").put("batch_id", batchId).put("uid", uid));
                    log("Registered with Verity");
                    String url = enc.readUrl();
                    lastTapUrl = url;
                    log("Read back: " + url);
                    JSONObject v = api.verifyAsStaff(url);
                    showVerdict(v, "Encoded ✔ and verified");
                    break;
                }
                case CHECK: {
                    String url = enc.readUrl();
                    lastTapUrl = url;
                    log("Tap URL: " + url);
                    JSONObject v = api.verifyAsStaff(url);
                    showVerdict(v, null);
                    break;
                }
                case RESET: {
                    boolean armed = onUiArmed();
                    if (!armed) { ui(() -> setStatus("Tick \"Armed\" first, then tap the tag to wipe it.", RED)); return; }
                    if (enc.isFactory()) {
                        ui(() -> setStatus("Already blank: this tag still has factory keys.", GREEN));
                        return;
                    }
                    log("Fetching this tag's current keys");
                    JSONObject r = api.encoder(new JSONObject().put("action", "reset_keys").put("uid", uid));
                    keys = keysFrom(r.getJSONObject("keys"));
                    enc.reset(keys);
                    api.encoder(new JSONObject().put("action", "mark_reset").put("uid", uid));
                    ui(() -> { resetArmed.setChecked(false); setStatus("Wiped ✔ Tag is back to factory keys and can be encoded again.", GREEN); });
                    break;
                }
            }
        } catch (VerityApi.ApiException e) {
            ui(() -> {
                setStatus(e.getMessage(), RED);
                if (e.code == 401) refreshSignIn();
            });
        } catch (TagLostException e) {
            ui(() -> setStatus("Tag moved away mid-write. Hold it still and try again. If Encode fails now, use Reset.", RED));
        } catch (IOException e) {
            ui(() -> setStatus("Connection problem: " + e.getMessage(), RED));
        } catch (DesfireException e) {
            String msg = e.isAuthFailure() && mode == Mode.ENCODE
                    ? "This tag isn't blank (factory key refused). Use Reset if it's one of ours."
                    : e.getMessage();
            ui(() -> setStatus(msg, RED));
        } catch (Exception e) {
            ui(() -> setStatus("Error: " + e.getMessage(), RED));
        } finally {
            if (keys != null) for (byte[] k : keys.k) Arrays.fill(k, (byte) 0);
            try { if (iso != null) iso.close(); } catch (IOException ignored) { }
            busy.set(false);
        }
    }

    /** NTAG213/215/216: test-only tags (no crypto). Same Encode / Check / Reset flow. */
    private void handleTestTag(NfcA a, String uid, Mode m) throws Exception {
        try {
            a.connect();
            a.setTimeout(1000);
            Ntag21xEncoder enc = new Ntag21xEncoder(a::transceive);
            Ntag21xEncoder.Model model = enc.identify();
            ui(() -> { logView.setText(""); setStatus("Working… keep the tag still", GREY); });
            log(model.name + " " + uid + " (TEST tag: no signature)");
            switch (m) {
                case ENCODE: {
                    String batchId = onUiBatch();
                    if (batchId == null) { ui(() -> setStatus("Pick a batch first (tap Refresh batches).", RED)); return; }
                    JSONObject r = api.encoder(new JSONObject().put("action", "register_21x").put("batch_id", batchId).put("uid", uid));
                    log("Registered as a test tag");
                    log("Writing URL and switching on the UID + counter mirror");
                    enc.encode(r.getString("url"));
                    String url = enc.readUrl();
                    lastTapUrl = url;
                    log("Read back: " + url);
                    showVerdict(api.verifyAsStaff(url), "Test tag encoded ✔ (not secure, for trying the flow)");
                    break;
                }
                case CHECK: {
                    String url = enc.readUrl();
                    lastTapUrl = url;
                    log("Tap URL: " + url);
                    showVerdict(api.verifyAsStaff(url), "Genuine ✔ (test tag)");
                    break;
                }
                case RESET: {
                    if (!onUiArmed()) { ui(() -> setStatus("Tick \"Armed\" first, then tap the tag to wipe it.", RED)); return; }
                    enc.reset();
                    try { api.encoder(new JSONObject().put("action", "mark_reset").put("uid", uid)); } catch (VerityApi.ApiException ignored) { }
                    ui(() -> { resetArmed.setChecked(false); setStatus("Wiped ✔ URL cleared and mirror off. Encode it again any time.", GREEN); });
                    break;
                }
            }
        } finally {
            try { a.close(); } catch (IOException ignored) { }
        }
    }

    private static Ntag424Encoder.TagKeys keysFrom(JSONObject k) throws Exception {
        return new Ntag424Encoder.TagKeys(Hex.decode(k.getString("k0")), Hex.decode(k.getString("k1")),
                Hex.decode(k.getString("k2")), Hex.decode(k.getString("k3")), Hex.decode(k.getString("k4")));
    }

    private void showVerdict(JSONObject v, String okLabel) {
        String verdict = v.optString("verdict");
        JSONObject tech = v.optJSONObject("tech");
        JSONObject product = v.optJSONObject("product");
        if (tech != null) {
            log("Server: " + tech.optString("reason"));
            if (tech.has("ctr")) log("Counter " + tech.optInt("ctr") + " (last accepted before: " + tech.opt("lastCtr") + ")");
        }
        boolean good = "GENUINE".equals(verdict);
        String text = good
                ? (okLabel != null ? okLabel : "Genuine ✔") + (product != null ? "\n" + product.optString("name") : "")
                : verdictLabel(verdict);
        ui(() -> setStatus(text, good ? GREEN : ORANGE));
    }

    private static String verdictLabel(String v) {
        switch (v) {
            case "REPLAYED": return "Blocked: this link was already used (copy)";
            case "FORGED": return "Blocked: signature doesn't match (fake or wrong brand key)";
            case "UNKNOWN_TAG": return "Not registered with Verity yet";
            case "CANCELLED_TAG": return "This tag is cancelled or was reset";
            case "BROKEN_LINK": return "No Verity link on this tag";
            default: return "Result: " + v;
        }
    }

    // ------------------------------------------------------------------ UI

    private void ui(Runnable r) { runOnUiThread(r); }

    private void log(String s) { ui(() -> logView.append("• " + s + "\n")); }

    private String onUiBatch() throws InterruptedException {
        final String[] out = new String[1];
        final Object lock = new Object();
        synchronized (lock) {
            runOnUiThread(() -> {
                int i = batchSpin.getSelectedItemPosition();
                out[0] = i >= 0 && i < batchIds.size() ? batchIds.get(i) : null;
                synchronized (lock) { lock.notify(); }
            });
            lock.wait(2000);
        }
        return out[0];
    }

    private boolean onUiArmed() throws InterruptedException {
        final boolean[] out = new boolean[1];
        final Object lock = new Object();
        synchronized (lock) {
            runOnUiThread(() -> { out[0] = resetArmed.isChecked(); synchronized (lock) { lock.notify(); } });
            lock.wait(2000);
        }
        return out[0];
    }

    private int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    private void buildUi() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(16), dp(16), dp(16), dp(24));
        scroll.addView(root);

        TextView title = new TextView(this);
        title.setText("CardForge · Verity product tags");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);
        TextView sub = new TextView(this);
        sub.setText("Encode NTAG 424 DNA tags that shoppers tap to check a product is genuine.");
        sub.setTextColor(GREY);
        root.addView(sub);

        // Sign in
        signInPanel = panel(root);
        emailIn = field(signInPanel, "Verity staff email", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS);
        passwordIn = field(signInPanel, "Password", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        button(signInPanel, "Sign in", v -> signIn());
        hint(signInPanel, "Create your account on the dashboard first: mariocannon.github.io/Tlv/dashboard");

        // Signed in
        workPanel = panel(root);
        who = new TextView(this);
        who.setTextColor(GREY);
        workPanel.addView(who);
        TextView bl = new TextView(this);
        bl.setText("Batch to encode into");
        bl.setPadding(0, dp(8), 0, 0);
        workPanel.addView(bl);
        batchSpin = new Spinner(this);
        workPanel.addView(batchSpin);
        LinearLayout btns = new LinearLayout(this);
        btns.setOrientation(LinearLayout.HORIZONTAL);
        workPanel.addView(btns);
        Button rb = new Button(this); rb.setText("Refresh batches"); rb.setAllCaps(false); rb.setOnClickListener(v -> loadBatches());
        Button db = new Button(this); db.setText("Open dashboard"); db.setAllCaps(false);
        db.setOnClickListener(v -> startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://mariocannon.github.io/Tlv/dashboard/"))));
        Button ob = new Button(this); ob.setText("Sign out"); ob.setAllCaps(false); ob.setOnClickListener(v -> { api.signOut(); refreshSignIn(); });
        btns.addView(rb, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        btns.addView(db, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        btns.addView(ob, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        LinearLayout tabRow = new LinearLayout(this);
        tabRow.setOrientation(LinearLayout.HORIZONTAL);
        tabRow.setPadding(0, dp(12), 0, dp(4));
        String[] names = {"Encode", "Check", "Reset"};
        for (int i = 0; i < 3; i++) {
            Button b = new Button(this);
            b.setText(names[i]);
            b.setAllCaps(false);
            final Mode md = Mode.values()[i];
            b.setOnClickListener(v -> setMode(md));
            tabRow.addView(b, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
            tabs[i] = b;
        }
        workPanel.addView(tabRow);
        modeHint = new TextView(this);
        modeHint.setTextColor(GREY);
        workPanel.addView(modeHint);
        resetPanel = panel(workPanel);
        resetArmed = check(resetPanel, "Armed (wipe the next tag tapped)");
        Button open = new Button(this);
        open.setText("Open last tap in browser (shopper view)");
        open.setAllCaps(false);
        open.setOnClickListener(v -> {
            if (lastTapUrl != null) startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(lastTapUrl)));
            else setStatus("Tap a tag first.", GREY);
        });
        workPanel.addView(open);

        status = new TextView(this);
        status.setTextSize(18);
        status.setTypeface(Typeface.DEFAULT_BOLD);
        status.setPadding(0, dp(12), 0, dp(8));
        root.addView(status);

        TextView logTitle = new TextView(this);
        logTitle.setText("Log");
        logTitle.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(logTitle);
        logView = new TextView(this);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setTextSize(12);
        logView.setTextIsSelectable(true);
        root.addView(logView);
        setContentView(scroll);
    }

    private void setMode(Mode m) {
        mode = m;
        for (int i = 0; i < tabs.length; i++) tabs[i].setEnabled(Mode.values()[i] != m);
        resetPanel.setVisibility(m == Mode.RESET ? View.VISIBLE : View.GONE);
        switch (m) {
            case ENCODE: modeHint.setText("Hold a blank NTAG 424 DNA tag to the phone. It gets its own keys, is registered to the batch above, then read back and checked. NTAG213/215/216 also work as TEST tags (no security, for trying the flow)."); break;
            case CHECK: modeHint.setText("Hold any Verity tag to the phone to see what the server decides, with the technical detail shoppers never see. Staff checks don't count as shopper scans."); break;
            case RESET: modeHint.setText("Wipes a Verity tag back to factory keys so you can reuse it for testing. It stops working as a Verity tag."); break;
        }
        setStatus("", GREY);
    }

    private void refreshSignIn() {
        boolean in = api.isSignedIn();
        signInPanel.setVisibility(in ? View.GONE : View.VISIBLE);
        workPanel.setVisibility(in ? View.VISIBLE : View.GONE);
        if (in) {
            who.setText("Signed in as " + api.email());
            loadBatches();
        }
    }

    private void signIn() {
        String email = emailIn.getText().toString().trim(), pw = passwordIn.getText().toString();
        setStatus("Signing in…", GREY);
        new Thread(() -> {
            try {
                api.signIn(email, pw);
                ui(() -> { passwordIn.setText(""); setStatus("", GREY); refreshSignIn(); });
            } catch (Exception e) {
                ui(() -> setStatus("Sign-in failed: " + e.getMessage(), RED));
            }
        }).start();
    }

    private void loadBatches() {
        new Thread(() -> {
            try {
                JSONArray arr = api.encoder(new JSONObject().put("action", "list_batches")).getJSONArray("batches");
                List<String> labels = new ArrayList<>();
                List<String> ids = new ArrayList<>();
                for (int i = 0; i < arr.length(); i++) {
                    JSONObject b = arr.getJSONObject(i);
                    if ("selftest".equals(b.optString("slug"))) continue;
                    ids.add(b.getString("id"));
                    labels.add(b.optString("brand") + " · " + b.optString("product") + " · " + b.optString("code")
                            + " (" + b.optInt("encoded") + "/" + b.optInt("planned") + ")");
                }
                ui(() -> {
                    batchIds.clear();
                    batchIds.addAll(ids);
                    ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, labels);
                    batchSpin.setAdapter(ad);
                    if (ids.isEmpty()) setStatus("No batches yet. Add one on the dashboard.", GREY);
                });
            } catch (VerityApi.ApiException e) {
                ui(() -> { setStatus(e.getMessage(), RED); if (e.code == 401) refreshSignIn(); });
            } catch (Exception e) {
                ui(() -> setStatus("Couldn't load batches: " + e.getMessage(), RED));
            }
        }).start();
    }

    private void setStatus(String text, int color) {
        status.setText(text);
        status.setTextColor(color);
    }

    private LinearLayout panel(LinearLayout parent) {
        LinearLayout p = new LinearLayout(this);
        p.setOrientation(LinearLayout.VERTICAL);
        p.setPadding(0, dp(8), 0, 0);
        parent.addView(p);
        return p;
    }

    private void hint(LinearLayout parent, String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextColor(GREY);
        t.setPadding(0, dp(4), 0, dp(8));
        parent.addView(t);
    }

    private EditText field(LinearLayout parent, String label, int inputType) {
        TextView l = new TextView(this);
        l.setText(label);
        l.setPadding(0, dp(8), 0, 0);
        parent.addView(l);
        EditText e = new EditText(this);
        e.setInputType(inputType);
        e.setSingleLine(true);
        parent.addView(e);
        return e;
    }

    private CheckBox check(LinearLayout parent, String text) {
        CheckBox c = new CheckBox(this);
        c.setText(text);
        parent.addView(c);
        return c;
    }

    private void button(LinearLayout parent, String text, View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setOnClickListener(l);
        parent.addView(b);
    }
}
