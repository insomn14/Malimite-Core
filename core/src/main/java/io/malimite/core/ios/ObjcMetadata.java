package io.malimite.core.ios;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Objective-C classes, categories and method implementations recovered from {@code __objc_classlist}/{@code __objc_catlist}. */
final class ObjcMetadata {

    /** One method implementation. {@code category} is null for methods declared on the class itself. */
    record Method(String cls, String selector, boolean classMethod, long imp, String category) {}

    private static final long FAST_DATA_MASK = 0x00007ffffffffff8L;
    private static final int MAX_METHODS = 200_000;
    private static final String CLASS_BIND_PREFIX = "_OBJC_CLASS_$_";

    private final MachOImage img;
    final List<Method> methods = new ArrayList<>();
    final Map<Long, Method> byImp = new HashMap<>();
    /** Every method sharing an implementation address (aliases/categories), in discovery order. */
    final Map<Long, List<Method>> allByImp = new HashMap<>();
    private final Map<Long, String> classNames = new java.util.concurrent.ConcurrentHashMap<>();

    ObjcMetadata(MachOImage img) {
        this.img = img;
        MachOImage.Section classlist = img.section("__objc_classlist");
        if (classlist != null)
            for (long p = 0; p + 8 <= classlist.size(); p += 8) readClass(img.ptr(classlist.addr() + p));
        for (String name : new String[] {"__objc_catlist", "__objc_nlcatlist"}) {
            MachOImage.Section cats = img.section(name);
            if (cats != null)
                for (long p = 0; p + 8 <= cats.size(); p += 8) readCategory(img.ptr(cats.addr() + p));
        }
    }

    /** Display name for a class_t at {@code classVm}, or null when unknown. */
    String classNameOf(long classVm) {
        if (classVm == 0) return null;
        String cached = classNames.get(classVm);
        if (cached != null) return cached;
        long ro = img.ptr(classVm + 32) & FAST_DATA_MASK;
        String raw = ro == 0 ? null : img.cstringAt(img.ptr(ro + 24));
        if (raw == null || raw.isEmpty()) return null;
        String name = prettyClass(raw);
        classNames.put(classVm, name);
        return name;
    }

    /** Class referenced from a pointer slot (e.g. {@code __objc_classrefs}): bound external class or local class_t. */
    String classRefName(long slotVm) {
        String bound = img.bindName(slotVm);
        if (bound != null) return bound.startsWith(CLASS_BIND_PREFIX) ? bound.substring(CLASS_BIND_PREFIX.length()) : null;
        return classNameOf(img.ptr(slotVm));
    }

    private void readClass(long cls) {
        if (cls == 0) return;
        String name = classNameOf(cls);
        if (name == null) return;
        long ro = img.ptr(cls + 32) & FAST_DATA_MASK;
        readMethodList(img.ptr(ro + 32), name, false, null);
        long meta = img.ptr(cls);
        if (meta != 0) {
            long metaRo = img.ptr(meta + 32) & FAST_DATA_MASK;
            if (metaRo != 0) readMethodList(img.ptr(metaRo + 32), name, true, null);
        }
    }

    private void readCategory(long cat) {
        if (cat == 0) return;
        String catName = img.cstringAt(img.ptr(cat));
        String bound = img.bindName(cat + 8);
        String cls = bound != null
                ? (bound.startsWith(CLASS_BIND_PREFIX) ? bound.substring(CLASS_BIND_PREFIX.length()) : bound)
                : classNameOf(img.ptr(cat + 8));
        if (cls == null || catName == null) return;
        readMethodList(img.ptr(cat + 16), cls, false, catName);
        readMethodList(img.ptr(cat + 24), cls, true, catName);
    }

    private void readMethodList(long list, String cls, boolean classMethod, String category) {
        if (list == 0) return;
        int ef = img.u32(list), count = img.u32(list + 4);
        boolean small = (ef & 0x80000000) != 0;
        int entsize = ef & 0xfffc;
        if (entsize == 0) entsize = small ? 12 : 24;
        if (count <= 0 || count > MAX_METHODS) return;
        for (int i = 0; i < count; i++) {
            long m = list + 8 + (long) i * entsize;
            String sel;
            long imp;
            if (small) {
                long nameAddr = m + img.u32(m);
                MachOImage.Section s = img.sectionOf(nameAddr);
                sel = s != null && s.type() == MachOImage.S_CSTRING_LITERALS
                        ? img.cstringAt(nameAddr)
                        : img.cstringAt(img.ptr(nameAddr));
                imp = m + 8 + img.u32(m + 8);
            } else {
                sel = img.cstringAt(img.ptr(m));
                imp = img.ptr(m + 16);
            }
            if (sel == null || imp == 0) continue;
            Method method = new Method(cls, sel, classMethod, imp, category);
            methods.add(method);
            byImp.putIfAbsent(imp, method);
            allByImp.computeIfAbsent(imp, k -> new ArrayList<>()).add(method);
        }
    }

    /** {@code _TtC7Module5Class} (Swift class exposed to ObjC) becomes {@code Module.Class}; anything else is unchanged. */
    static String prettyClass(String raw) {
        if (!raw.startsWith("_TtC")) return raw;
        int[] pos = {4};
        StringBuilder out = new StringBuilder();
        while (pos[0] < raw.length()) {
            String part = lengthPrefixed(raw, pos);
            if (part == null) break;
            if (out.length() > 0) out.append('.');
            out.append(part);
        }
        return out.length() == 0 ? raw : out.toString();
    }

    private static String lengthPrefixed(String s, int[] pos) {
        int p = pos[0], n = 0, digits = 0;
        while (p < s.length() && Character.isDigit(s.charAt(p))) { n = n * 10 + (s.charAt(p) - '0'); p++; digits++; }
        if (digits == 0 || n == 0 || p + n > s.length()) return null;
        pos[0] = p + n;
        return s.substring(p, p + n);
    }
}
