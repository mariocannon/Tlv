package nz.cardforge.verity;

import android.content.SharedPreferences;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.TimeZone;

/** Talks to the Verity Supabase project: staff sign-in, the encoder function and the verify function. */
public final class VerityApi {

    // Public project settings. The anon key is meant to be public; staff rights come from the signed-in user.
    public static final String URL_BASE = "https://emcuwvuouggvdwnowlwr.supabase.co";
    public static final String ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVtY3V3dnVvdWdndmR3bm93bHdyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTUzOTczNDIsImV4cCI6MjExMDk3MzM0Mn0.AezCpoLohG9fX3pXJJkWA6iCxWEtwCJD31hcdyRk4UM";

    public static final class ApiException extends Exception {
        public final int code;
        ApiException(int code, String msg) { super(msg); this.code = code; }
    }

    private final SharedPreferences prefs;
    private String accessToken;
    private long expiresAtMs;

    public VerityApi(SharedPreferences prefs) { this.prefs = prefs; }

    public boolean isSignedIn() { return prefs.getString("refresh", null) != null; }

    public String email() { return prefs.getString("email", ""); }

    public void signOut() {
        accessToken = null;
        prefs.edit().remove("refresh").remove("email").apply();
    }

    public void signIn(String email, String password) throws IOException, ApiException, JSONException {
        JSONObject body = new JSONObject().put("email", email).put("password", password);
        JSONObject r = http("POST", URL_BASE + "/auth/v1/token?grant_type=password", body.toString(), null);
        store(r);
        prefs.edit().putString("email", email).apply();
    }

    private void store(JSONObject r) throws JSONException {
        accessToken = r.getString("access_token");
        expiresAtMs = System.currentTimeMillis() + r.optLong("expires_in", 3600) * 1000L;
        prefs.edit().putString("refresh", r.getString("refresh_token")).apply();
    }

    private String token() throws IOException, ApiException, JSONException {
        if (accessToken != null && System.currentTimeMillis() < expiresAtMs - 60_000) return accessToken;
        String refresh = prefs.getString("refresh", null);
        if (refresh == null) throw new ApiException(401, "Sign in first");
        try {
            store(http("POST", URL_BASE + "/auth/v1/token?grant_type=refresh_token",
                    new JSONObject().put("refresh_token", refresh).toString(), null));
        } catch (ApiException e) {
            signOut();
            throw new ApiException(401, "Session expired. Sign in again.");
        }
        return accessToken;
    }

    /** Calls the encoder edge function. */
    public JSONObject encoder(JSONObject body) throws IOException, ApiException, JSONException {
        return http("POST", URL_BASE + "/functions/v1/encoder", body.toString(), token());
    }

    /** Runs a tap URL through the verify function as a staff check (qc=1), so it shows technical detail. */
    public JSONObject verifyAsStaff(String tapUrl) throws IOException, ApiException, JSONException {
        String b = param(tapUrl, "b"), p = param(tapUrl, "p"), m = param(tapUrl, "m"), u = param(tapUrl, "u"), s = param(tapUrl, "s");
        String url = URL_BASE + "/functions/v1/verify?qc=1&b=" + enc(b) + "&p=" + enc(p) + "&m=" + enc(m)
                + (u != null ? "&u=" + enc(u) : "") + (s != null ? "&s=" + enc(s) : "")
                + "&tz=" + enc(TimeZone.getDefault().getID());
        return http("GET", url, null, token());
    }

    private static String enc(String s) throws IOException {
        return URLEncoder.encode(s == null ? "" : s, "UTF-8");
    }

    static String param(String url, String key) {
        int q = url.indexOf('?');
        if (q < 0) return null;
        for (String kv : url.substring(q + 1).split("&")) {
            if (kv.startsWith(key + "=")) return kv.substring(key.length() + 1);
        }
        return null;
    }

    private JSONObject http(String method, String url, String body, String bearer) throws IOException, ApiException, JSONException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod(method);
        c.setConnectTimeout(10_000);
        c.setReadTimeout(15_000);
        c.setRequestProperty("apikey", ANON_KEY);
        c.setRequestProperty("Authorization", "Bearer " + (bearer != null ? bearer : ANON_KEY));
        if (body != null) {
            c.setDoOutput(true);
            c.setRequestProperty("Content-Type", "application/json");
            try (OutputStream os = c.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
        }
        int code = c.getResponseCode();
        InputStream in = code >= 400 ? c.getErrorStream() : c.getInputStream();
        String text = "";
        if (in != null) {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) buf.write(b, 0, n);
            in.close();
            text = buf.toString("UTF-8");
        }
        c.disconnect();
        JSONObject json;
        try {
            json = text.isEmpty() ? new JSONObject() : new JSONObject(text);
        } catch (JSONException e) {
            json = new JSONObject().put("error", text.length() > 200 ? text.substring(0, 200) : text);
        }
        if (code >= 400) {
            String msg = json.optString("error_description", json.optString("msg", json.optString("error", "HTTP " + code)));
            throw new ApiException(code, msg);
        }
        return json;
    }
}
