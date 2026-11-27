package io.malimite.core.ios;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Names the import a call lands on by replaying the stub's own instructions ({@code adrp/add/ldr/br}) through
 * {@link Tracker}. Handles {@code __stubs}, {@code __auth_stubs} and {@code __objc_stubs}; the latter also fix the selector in x1.
 */
final class StubResolver {

    /** @param name import name without the Mach-O underscore; @param sel preset selector for {@code __objc_stubs}, else null */
    record Callee(String name, String sel) {}

    private static final int MAX_STUB_INSNS = 12;

    private final MachOImage img;
    private final ObjcMetadata objc;
    private final Map<Long, Optional<Callee>> cache = new ConcurrentHashMap<>();

    StubResolver(MachOImage img, ObjcMetadata objc) {
        this.img = img;
        this.objc = objc;
    }

    boolean isStubSection(long addr) {
        MachOImage.Section s = img.sectionOf(addr);
        return s != null && (s.name().equals("__stubs") || s.name().equals("__auth_stubs") || s.name().equals("__objc_stubs"));
    }

    /** The import a call to {@code addr} reaches, or null when {@code addr} is not a recognised stub. */
    Callee resolve(long addr) {
        if (!isStubSection(addr)) return null;
        return cache.computeIfAbsent(addr, this::run).orElse(null);
    }

    private Optional<Callee> run(long addr) {
        Tracker t = new Tracker(img, objc);
        long off = img.offsetOf(addr);
        if (off < 0) return Optional.empty();
        for (int i = 0; i < MAX_STUB_INSNS && off + 4 * (i + 1) <= img.buf.limit(); i++) {
            Arm64Decoder.Insn in = Arm64Decoder.decode(img.buf.getInt((int) off + 4 * i), addr + 4L * i);
            if (in.op() == Arm64Decoder.Op.BR) {
                Val target = t.reg(in.rn());
                if (target == null || target.k != Val.K.SYM) return Optional.empty();
                Val sel = t.reg(1);
                return Optional.of(new Callee(target.s, sel != null && sel.k == Val.K.SEL ? sel.s : null));
            }
            if (in.op() == Arm64Decoder.Op.RET || in.op() == Arm64Decoder.Op.B || in.op() == Arm64Decoder.Op.BL)
                return Optional.empty();
            t.step(in);
        }
        return Optional.empty();
    }
}
