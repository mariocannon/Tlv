package nz.cardforge.ntag;

import nz.cardforge.desfire.DesfireException;
import nz.cardforge.desfire.Hex;

/** NTAG213/215/216 test-tag encoder tests (plain Java): ./run-tests.sh */
public final class Ntag21xTests {
    static int passed = 0;
    static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        passed++; System.out.println("  ok  " + name);
    }
    static final String TEMPLATE = "https://mariocannon.github.io/Tlv/t/?b=demo&u=00000000000000x000000";
    static String param(String url, String k) {
        for (String kv : url.substring(url.indexOf('?') + 1).split("&")) if (kv.startsWith(k + "=")) return kv.substring(k.length() + 1);
        return null;
    }

    public static void main(String[] a) throws Exception {
        System.out.println("NTAG21x test tags");
        byte[] uid = Hex.decode("04A1B2C3D4E5F6");
        int[] sizes = { 0x0F, 0x11, 0x13 };
        String[] names = { "NTAG213", "NTAG215", "NTAG216" };
        for (int i = 0; i < 3; i++) {
            Ntag21xSim sim = new Ntag21xSim(sizes[i], uid);
            Ntag21xEncoder enc = new Ntag21xEncoder(sim);
            check(enc.identify().name.equals(names[i]), names[i] + " identified");
            enc.encode(TEMPLATE);
            check((sim.mem[sim.cfg0 * 4] & 0x04) != 0, names[i] + " keeps STRG_MOD_EN");
            check((sim.mem[sim.cfg0 * 4 + 4] & 0x10) != 0, names[i] + " NFC counter enabled");
            sim.powerCycle();
            String u1 = enc.readUrl();
            check(u1.startsWith("https://mariocannon.github.io/Tlv/t/?b=demo&u="), names[i] + " URL intact");
            check(param(u1, "u").equals("04A1B2C3D4E5F6x000001"), names[i] + " mirror = UID x counter 1 (" + param(u1, "u") + ")");
            check(param(u1, "b").equals("demo"), names[i] + " brand param intact");
            sim.powerCycle();
            String u2 = enc.readUrl();
            check(param(u2, "u").equals("04A1B2C3D4E5F6x000002"), names[i] + " counter goes up on next tap");
            enc.reset();
            sim.powerCycle();
            boolean threw = false;
            try { enc.readUrl(); } catch (DesfireException e) { threw = true; }
            check(threw, names[i] + " reset clears the URL");
            check((sim.mem[sim.cfg0 * 4] & 0xC0) == 0, names[i] + " reset turns mirror off");
            enc.encode(TEMPLATE);
            sim.powerCycle();
            check(param(enc.readUrl(), "u").startsWith("04A1B2C3D4E5F6x"), names[i] + " can be re-encoded after reset");
        }
        // Every mirror byte position (0..3) works: vary the URL length.
        for (int pad = 0; pad < 4; pad++) {
            Ntag21xSim sim = new Ntag21xSim(0x0F, uid);
            Ntag21xEncoder enc = new Ntag21xEncoder(sim);
            String t = "https://mariocannon.github.io/Tlv/t/?b=demo" + "x".repeat(pad) + "&u=00000000000000x000000";
            enc.encode(t);
            sim.powerCycle();
            check(param(enc.readUrl(), "u").equals("04A1B2C3D4E5F6x000001"), "mirror byte offset case " + pad);
        }
        // Password-protected tag is refused, not half-written.
        Ntag21xSim locked = new Ntag21xSim(0x13, uid);
        locked.mem[locked.cfg0 * 4 + 3] = 0x04;
        boolean refused = false;
        try { new Ntag21xEncoder(locked).encode(TEMPLATE); } catch (DesfireException e) { refused = e.getMessage().contains("password"); }
        check(refused, "password-protected tag refused");
        // Template without u= is refused.
        boolean noU = false;
        try { new Ntag21xEncoder(new Ntag21xSim(0x0F, uid)).encode("https://x.example/t/?b=demo"); } catch (DesfireException e) { noU = true; }
        check(noU, "template without u= refused");
        // Too-long URL on an NTAG213 is refused.
        boolean tooLong = false;
        try { new Ntag21xEncoder(new Ntag21xSim(0x0F, uid)).encode("https://x.example/" + "a".repeat(150) + "?b=d&u=00000000000000x000000"); } catch (DesfireException e) { tooLong = true; }
        check(tooLong, "URL too long for NTAG213 refused");
        System.out.println("NTAG21x: " + passed + " passed");
    }
}
