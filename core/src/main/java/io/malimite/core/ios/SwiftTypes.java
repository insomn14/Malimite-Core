package io.malimite.core.ios;

import java.util.HashMap;
import java.util.Map;

/**
 * Names the implementations in the vtables of non-generic Swift classes ({@code __swift5_types}). Stripped binaries carry
 * no Swift symbols, but each class descriptor lists its methods (kind + implementation) in declaration order, so a
 * function can at least be placed in {@code Module.Type} as {@code getter_3}/{@code method_7}/{@code init_1}.
 * Layout: swift/ABI/Metadata.h (TargetClassDescriptor and its trailing objects).
 */
final class SwiftTypes {

    /** @param cls {@code Module.Type} (the same form {@link ObjcMetadata#prettyClass} gives a bridged class) */
    record Method(String cls, String kind, int slot) {
        String functionName() { return kind + "_" + slot; }
    }

    private static final int KIND_MASK = 0x1f;
    private static final int KIND_CLASS = 16;
    private static final int KIND_MODULE = 0;
    private static final int FLAG_GENERIC = 0x80;
    private static final int KF_HAS_VTABLE = 1 << 15;
    private static final int KF_HAS_RESILIENT_SUPERCLASS = 1 << 13;
    private static final int CLASS_DESCRIPTOR_SIZE = 44;       // TypeContextDescriptor (20) + class fields (24)
    private static final int SINGLETON_INIT_SIZE = 12;
    private static final int FOREIGN_INIT_SIZE = 4;
    private static final int MAX_PARENT_DEPTH = 8;
    private static final int MAX_VTABLE = 100_000;
    private static final String[] KINDS = {"method", "init", "getter", "setter", "modify", "read"};

    private final MachOImage img;
    /** Implementation address to its method; addresses several entries share (e.g. a "deleted method" stub) are left out. */
    final Map<Long, Method> byImp = new HashMap<>();

    SwiftTypes(MachOImage img) {
        this.img = img;
        MachOImage.Section types = img.section("__swift5_types");
        if (types == null) return;
        Map<Long, Integer> uses = new HashMap<>();
        for (long p = 0; p + 4 <= types.size(); p += 4) {
            long entry = types.addr() + p;
            int rel = img.u32(entry);
            if ((rel & 1) != 0 || rel == 0) continue;           // indirect: descriptor lives in another image
            readClass(entry + rel, uses);
        }
        MachOImage.Section protos = img.section("__swift5_proto");
        if (protos != null)
            for (long p = 0; p + 4 <= protos.size(); p += 4) {
                long entry = protos.addr() + p;
                readConformance(entry + img.u32(entry), uses);
            }
        byImp.keySet().removeIf(a -> uses.getOrDefault(a, 0) > 1);
    }

    private static final int CF_TYPE_KIND_MASK = 0x7 << 3, CF_CONDITIONAL = 0xff << 8,
            CF_RESILIENT = 1 << 16, CF_GENERIC_TABLE = 1 << 17;
    private static final int MAX_WITNESSES = 64;

    /**
     * A protocol conformance of a type defined in this image names the entries of its witness table. Entry 0 is the
     * conformance descriptor, then one pointer per protocol requirement. Only plain tables are read (not generic,
     * conditional or resilient). Layout: ProtocolConformanceDescriptor in swift/ABI/Metadata.h.
     */
    private void readConformance(long desc, Map<Long, Integer> uses) {
        int flags = img.u32(desc + 12);
        if ((flags & (CF_RESILIENT | CF_GENERIC_TABLE | CF_CONDITIONAL)) != 0 || (flags & CF_TYPE_KIND_MASK) != 0) return;
        int typeRel = img.u32(desc + 4), tableRel = img.u32(desc + 8);
        if (typeRel == 0 || tableRel == 0 || (typeRel & 1) != 0) return;   // not a direct descriptor of a local type
        String type = qualifiedName(desc + 4 + typeRel, 0);
        if (type == null) return;
        long table = desc + 8 + tableRel;

        int protoRel = img.u32(desc);
        long protoRef = desc + (protoRel & ~1);
        String proto;
        int count = MAX_WITNESSES;
        if ((protoRel & 1) != 0) {                                  // indirect: GOT slot bound to the protocol descriptor symbol
            String bound = img.bindName(protoRef);
            if (bound == null) return;
            proto = bound.replaceFirst("^_?\\$s", "").replaceFirst("Mp$", "");
        } else {
            long pd = protoRef;
            String n = img.cstringAt(pd + 8 + img.u32(pd + 8));
            if (n == null || n.isEmpty()) return;
            proto = n;
            int req = img.u32(pd + 16);
            if (req > 0 && req < MAX_WITNESSES) count = req;
        }
        MachOImage.Section text = img.section("__text");
        if (text == null) return;
        for (int i = 0; i < count; i++) {
            long impl = img.ptr(table + 8L * (i + 1));
            if (impl < text.addr() || impl >= text.addr() + text.size()) {
                if (count == MAX_WITNESSES) break;                  // unknown length: stop at the first non-code word
                continue;
            }
            uses.merge(impl, 1, Integer::sum);
            byImp.putIfAbsent(impl, new Method(type, proto + ".witness", i));
        }
    }

    private void readClass(long desc, Map<Long, Integer> uses) {
        int flags = img.u32(desc);
        if ((flags & KIND_MASK) != KIND_CLASS || (flags & FLAG_GENERIC) != 0) return;
        int kf = flags >>> 16;
        if ((kf & KF_HAS_VTABLE) == 0) return;
        String cls = qualifiedName(desc, 0);
        if (cls == null) return;
        long q = desc + CLASS_DESCRIPTOR_SIZE;
        if ((kf & KF_HAS_RESILIENT_SUPERCLASS) != 0) q += 4;
        int init = kf & 3;
        if (init == 1) q += SINGLETON_INIT_SIZE;
        else if (init == 2) q += FOREIGN_INIT_SIZE;
        int size = img.u32(q + 4);
        if (size <= 0 || size > MAX_VTABLE) return;
        q += 8;
        for (int slot = 0; slot < size; slot++) {
            long m = q + 8L * slot;
            int rel = img.u32(m + 4);
            if (rel == 0) continue;                             // method removed by the linker
            long impl = m + 4 + rel;
            uses.merge(impl, 1, Integer::sum);
            int kind = img.u32(m) & 0xf;
            byImp.putIfAbsent(impl, new Method(cls, kind < KINDS.length ? KINDS[kind] : "k" + kind, slot));
        }
    }

    /** {@code Module.Outer.Inner} for a context descriptor; null when its name cannot be read. */
    private String qualifiedName(long desc, int depth) {
        int flags = img.u32(desc);
        int nameRel = img.u32(desc + 8);
        if (nameRel == 0) return null;
        String name = img.cstringAt(desc + 8 + nameRel);
        if (name == null || name.isEmpty()) return null;
        if ((flags & KIND_MASK) == KIND_MODULE || depth >= MAX_PARENT_DEPTH) return name;
        int parentRel = img.u32(desc + 4);
        if (parentRel == 0 || (parentRel & 1) != 0) return name; // none, or in another image
        String parent = qualifiedName(desc + 4 + parentRel, depth + 1);
        return parent == null ? name : parent + "." + name;
    }
}
