package nz.cardforge;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.Date;
import java.util.Locale;

/** In-memory log of reader <-> phone APDUs, shown in the Phone tab (used to discover what the reader sends). */
final class ApduLog {
    private static final int MAX = 300;
    private static final ArrayDeque<String> lines = new ArrayDeque<>();
    private static final SimpleDateFormat TIME = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
    private static volatile Runnable listener;

    private ApduLog() {}

    static void add(String line) {
        synchronized (lines) {
            lines.addLast(TIME.format(new Date()) + "  " + line);
            while (lines.size() > MAX) lines.removeFirst();
        }
        Runnable l = listener;
        if (l != null) l.run();
    }

    static String dump() {
        synchronized (lines) {
            StringBuilder sb = new StringBuilder();
            for (String s : lines) sb.append(s).append('\n');
            return sb.length() == 0 ? "(no reader traffic yet)" : sb.toString();
        }
    }

    static void clear() {
        synchronized (lines) {
            lines.clear();
        }
        Runnable l = listener;
        if (l != null) l.run();
    }

    static void setListener(Runnable r) { listener = r; }
}
