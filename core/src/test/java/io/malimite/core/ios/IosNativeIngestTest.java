package io.malimite.core.ios;

import io.malimite.core.SqliteStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Builds a tiny arm64 Mach-O in memory: class {@code Foo} with method {@code login:} whose body calls
 * {@code NSLog("password=%@")} through a {@code __stubs} entry and then {@code objc_msgSend(self, "setObject:forKey:", ...)}
 * through a second stub, with the GOT slots bound by classic dyld bind opcodes.
 */
class IosNativeIngestTest {

    static final long BASE = 0x100000000L;
    static final int TEXT = 0x1000, STUBS = 0x1100, CSTR = 0x1200, METH = 0x1300;
    static final int DATA = 0x4000, GOT = DATA, SELREF = DATA + 0x10, CLASSLIST = DATA + 0x20,
            RO = DATA + 0x100, RO_META = DATA + 0x1c0, MLIST = DATA + 0x200, CLS = DATA + 0x300, META = DATA + 0x340;
    static final int LINKEDIT = 0x8000, FSTARTS = 0x8040, SIZE = 0x8100;

    static int adrp(int rd, long pc, long target) {
        long imm = ((target & ~0xfffL) - (pc & ~0xfffL)) >> 12;
        return 0x90000000 | (int) ((imm & 3) << 29) | (int) (((imm >> 2) & 0x7ffff) << 5) | rd;
    }
    static int addImm(int rd, int rn, int imm) { return 0x91000000 | (imm << 10) | (rn << 5) | rd; }
    static int ldrX(int rt, int rn, int imm) { return 0xf9400000 | ((imm >> 3) << 10) | (rn << 5) | rt; }
    static int bl(long pc, long target) { return 0x94000000 | (int) (((target - pc) >> 2) & 0x3ffffff); }

    static byte[] tinyApp() {
        ByteBuffer b = ByteBuffer.allocate(SIZE).order(ByteOrder.LITTLE_ENDIAN);
        // header + load commands
        b.putInt(0, 0xFEEDFACF).putInt(4, 0x0100000C).putInt(12, 2);
        int p = 32, ncmds = 0;
        p = segment(b, p, "__TEXT", BASE, 0x4000, 0, 0x4000, new String[][] {
                {"__text", "__TEXT", "" + (BASE + TEXT), "64", "" + TEXT, "0x80000400"},
                {"__stubs", "__TEXT", "" + (BASE + STUBS), "24", "" + STUBS, "0x80000408"},
                {"__cstring", "__TEXT", "" + (BASE + CSTR), "64", "" + CSTR, "2"},
                {"__objc_methname", "__TEXT", "" + (BASE + METH), "64", "" + METH, "2"}});
        ncmds++;
        p = segment(b, p, "__DATA", BASE + DATA, 0x4000, DATA, 0x4000, new String[][] {
                {"__got", "__DATA", "" + (BASE + GOT), "16", "" + GOT, "6"},
                {"__objc_selrefs", "__DATA", "" + (BASE + SELREF), "8", "" + SELREF, "0x10000005"},
                {"__objc_classlist", "__DATA", "" + (BASE + CLASSLIST), "8", "" + CLASSLIST, "0x10000000"},
                {"__objc_const", "__DATA", "" + (BASE + RO), "512", "" + RO, "0"},
                {"__objc_data", "__DATA", "" + (BASE + CLS), "128", "" + CLS, "0"}});
        ncmds++;
        p = segment(b, p, "__LINKEDIT", BASE + LINKEDIT, 0x100, LINKEDIT, 0x100, new String[0][]);
        ncmds++;
        b.putInt(p, 0x80000022).putInt(p + 4, 48).putInt(p + 16, LINKEDIT).putInt(p + 20, 48);  // LC_DYLD_INFO_ONLY: bind
        p += 48; ncmds++;
        b.putInt(p, 0x26).putInt(p + 4, 16).putInt(p + 8, FSTARTS).putInt(p + 12, 4);           // LC_FUNCTION_STARTS
        p += 16; ncmds++;
        b.putInt(16, ncmds).putInt(20, p - 32);

        // strings
        str(b, CSTR, "password=%@"); str(b, CSTR + 0x20, "Foo");
        str(b, METH, "login:"); str(b, METH + 0x10, "setObject:forKey:"); str(b, METH + 0x30, "v24@0:8@16");

        // login: -> [self setObject:param_3 forKey:param_4]; NSLog("password=%@")
        long fn = BASE + TEXT;
        int[] code = {
                adrp(1, fn, BASE + SELREF), ldrX(1, 1, SELREF & 0xfff), bl(fn + 8, BASE + STUBS + 12),
                adrp(0, fn + 12, BASE + CSTR), addImm(0, 0, CSTR & 0xfff), bl(fn + 20, BASE + STUBS),
                0xd65f03c0};
        for (int i = 0; i < code.length; i++) b.putInt(TEXT + 4 * i, code[i]);
        // stubs: adrp x16, got ; ldr x16,[x16,#slot] ; br x16
        for (int s = 0; s < 2; s++) {
            long pc = BASE + STUBS + 12L * s;
            b.putInt(STUBS + 12 * s, adrp(16, pc, BASE + GOT));
            b.putInt(STUBS + 12 * s + 4, ldrX(16, 16, (GOT & 0xfff) + 8 * s));
            b.putInt(STUBS + 12 * s + 8, 0xd61f0200);
        }
        // ObjC: selref, classlist, class_t, class_ro, method list
        b.putLong(SELREF, BASE + METH + 0x10);
        b.putLong(CLASSLIST, BASE + CLS);
        b.putLong(CLS, BASE + META).putLong(CLS + 32, BASE + RO);
        b.putLong(META + 32, BASE + RO_META);
        b.putLong(RO + 24, BASE + CSTR + 0x20).putLong(RO + 32, BASE + MLIST);
        b.putInt(MLIST, 24).putInt(MLIST + 4, 1);
        b.putLong(MLIST + 8, BASE + METH).putLong(MLIST + 16, BASE + METH + 0x30).putLong(MLIST + 24, fn);
        // bind opcodes: _NSLog -> got+0, _objc_msgSend -> got+8
        int q = LINKEDIT;
        q = bytes(b, q, 0x40); q = cstr(b, q, "_NSLog"); q = bytes(b, q, 0x51, 0x71, 0x00, 0x90);
        q = bytes(b, q, 0x40); q = cstr(b, q, "_objc_msgSend"); q = bytes(b, q, 0x51, 0x71, 0x08, 0x90, 0x00);
        // function starts: ULEB(0x1000), end
        bytes(b, FSTARTS, 0x80, 0x20, 0x00);
        return b.array();
    }

    static int segment(ByteBuffer b, int p, String name, long vm, long vmsize, long fileoff, long filesize, String[][] sects) {
        b.putInt(p, 0x19).putInt(p + 4, 72 + 80 * sects.length);
        cstrFixed(b, p + 8, name);
        b.putLong(p + 24, vm).putLong(p + 32, vmsize).putLong(p + 40, fileoff).putLong(p + 48, filesize).putInt(p + 64, sects.length);
        int q = p + 72;
        for (String[] s : sects) {
            cstrFixed(b, q, s[0]); cstrFixed(b, q + 16, s[1]);
            b.putLong(q + 32, Long.decode(s[2])).putLong(q + 40, Long.decode(s[3]))
                    .putInt(q + 48, Integer.decode(s[4])).putInt(q + 64, (int) (long) Long.decode(s[5]));
            q += 80;
        }
        return p + 72 + 80 * sects.length;
    }

    static void cstrFixed(ByteBuffer b, int at, String s) {
        for (int i = 0; i < s.length(); i++) b.put(at + i, (byte) s.charAt(i));
    }
    static void str(ByteBuffer b, int at, String s) { cstrFixed(b, at, s); b.put(at + s.length(), (byte) 0); }
    static int cstr(ByteBuffer b, int at, String s) { str(b, at, s); return at + s.length() + 1; }
    static int bytes(ByteBuffer b, int at, int... v) { for (int x : v) b.put(at++, (byte) x); return at; }

    @Test
    void liftsObjcMethodWithResolvedImportSelectorAndLiteral(@TempDir Path tmp) throws Exception {
        Path bin = tmp.resolve("App");
        Files.write(bin, tinyApp());
        Path db = tmp.resolve("t.sqlite");
        try (SqliteStore store = new SqliteStore(db.toString())) {
            IosNativeIngest.Result r = IosNativeIngest.ingest(bin, store, "App", List.of());
            assertEquals(1, r.withCode());
            assertTrue(r.imports() >= 2);

            SqliteStore.DecompilationResult login = store.getAllDecompiledFunctions("App").stream()
                    .filter(f -> f.functionName().equals("login:")).findFirst().orElseThrow();
            assertEquals("Foo", login.className());
            assertEquals("NATIVE", login.origin());
            String code = login.decompiledCode();
            assertTrue(code.startsWith("// Class: Foo\n// Function: login:\n\n"), code);
            assertTrue(code.contains("NSLog(\"password=%@\")"), code);
            assertTrue(code.contains("objc_msgSend(self, \"setObject:forKey:\", param_3, param_4);"), code);

            assertTrue(store.getMachoStrings("App", 100).stream().anyMatch(m -> "password=%@".equals(m.get("value"))));
            assertEquals(List.of("login:"), store.getClassesAndFunctions("App").get("Foo"));
            assertTrue(store.getClassesAndFunctions("App").get("Imports").contains("_NSLog"));
        }
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + db); Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT targetFunction, targetClass FROM FunctionReferences ORDER BY lineNumber")) {
            assertTrue(rs.next());
            assertEquals("setObject:forKey:", rs.getString(1));
            assertTrue(rs.next());
            assertEquals("NSLog", rs.getString(1));
        }
    }

    @Test
    void rejectsEncryptedBinary(@TempDir Path tmp) throws Exception {
        byte[] app = tinyApp();
        ByteBuffer b = ByteBuffer.wrap(app).order(ByteOrder.LITTLE_ENDIAN);
        int p = 32;
        for (int i = 0, n = b.getInt(16); i < n; i++) p += b.getInt(p + 4);
        b.putInt(p, 0x2C).putInt(p + 4, 24).putInt(p + 16, 1);  // LC_ENCRYPTION_INFO_64 cryptid=1
        b.putInt(16, b.getInt(16) + 1).putInt(20, b.getInt(20) + 24);
        Path bin = tmp.resolve("Enc");
        Files.write(bin, app);
        try (SqliteStore store = new SqliteStore(tmp.resolve("e.sqlite").toString())) {
            assertThrows(java.io.IOException.class, () -> IosNativeIngest.ingest(bin, store, "Enc", List.of()));
        }
    }

    @Test
    void decoderRecognisesAddressAndBranchForms() {
        long pc = BASE + TEXT;
        Arm64Decoder.Insn a = Arm64Decoder.decode(adrp(3, pc, BASE + 0x5000), pc);
        assertEquals(Arm64Decoder.Op.ADRP, a.op());
        assertEquals(3, a.rd());
        assertEquals(BASE + 0x5000, a.imm());
        Arm64Decoder.Insn c = Arm64Decoder.decode(bl(pc, BASE + STUBS), pc);
        assertEquals(Arm64Decoder.Op.BL, c.op());
        assertEquals(BASE + STUBS, c.imm());
        assertEquals(Arm64Decoder.Op.RET, Arm64Decoder.decode(0xd65f03c0, pc).op());
        assertEquals(Arm64Decoder.Op.BR, Arm64Decoder.decode(0xd61f0200, pc).op());
        Arm64Decoder.Insn mov = Arm64Decoder.decode(0xaa0203e1, pc);  // mov x1, x2
        assertEquals(Arm64Decoder.Op.MOV_REG, mov.op());
        assertEquals(1, mov.rd());
        assertEquals(2, mov.rm());
        assertEquals(Arm64Decoder.Op.MOVZ, Arm64Decoder.decode(0x52800020, pc).op());  // mov w0, #1
        // ccmp must not claim to clobber a register named by its nzcv bits
        assertEquals(-1, Arm64Decoder.decode(0xfa400804, pc).rd());
    }

    @Test
    void prettyClassKeepsObjcNamesAndSplitsSwiftOnes() {
        assertEquals("NSObject", ObjcMetadata.prettyClass("NSObject"));
        assertEquals("Krom.LoginViewController", ObjcMetadata.prettyClass("_TtC4Krom19LoginViewController"));
    }
}
