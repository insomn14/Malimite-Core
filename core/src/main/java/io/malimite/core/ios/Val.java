package io.malimite.core.ios;

/** What the lifter knows a register holds: a constant, a resolved literal/selector/class/import, an address, or a call result. */
final class Val {

    enum K { CONST, STR, CFSTR, SEL, CLS, SYM, ADDR, RET, NAMED, MEM }

    private static final int MAX_LITERAL = 300;

    final K k;
    final long n;
    final String s;

    private Val(K k, long n, String s) { this.k = k; this.n = n; this.s = s; }

    static Val konst(long n) { return new Val(K.CONST, n, null); }
    static Val str(String s) { return new Val(K.STR, 0, s); }
    static Val cfstr(String s) { return new Val(K.CFSTR, 0, s); }
    static Val sel(String s) { return new Val(K.SEL, 0, s); }
    static Val cls(String s) { return new Val(K.CLS, 0, s); }
    static Val addr(long a) { return new Val(K.ADDR, a, null); }
    /** Result of a call, shown inline as its expression (or {@code x0} when the expression is long). */
    static Val ret(String expr) { return new Val(K.RET, 0, expr); }
    /** A field read from a parameter or another field ({@code *(self + 0x30)}): ivars, struct members. */
    static Val mem(String expr) { return new Val(K.MEM, 0, expr); }
    static Val named(String name) { return new Val(K.NAMED, 0, name); }

    /** Imported symbol; class symbols become class values and the Mach-O leading underscore is dropped. */
    static Val sym(String name) {
        if (name.startsWith("_OBJC_CLASS_$_")) return cls(name.substring("_OBJC_CLASS_$_".length()));
        if (name.startsWith("_OBJC_METACLASS_$_")) return cls(name.substring("_OBJC_METACLASS_$_".length()));
        return new Val(K.SYM, 0, name.startsWith("_") ? name.substring(1) : name);
    }

    boolean isLiteral() { return k == K.STR || k == K.CFSTR || k == K.SEL || k == K.CLS || k == K.SYM; }

    String show() {
        return switch (k) {
            case CONST -> n >= 0 && n < 10 ? Long.toString(n) : n < 0 && n > -10 ? Long.toString(n) : "0x" + Long.toHexString(n);
            case STR, SEL -> quote(s);
            case CFSTR -> "@" + quote(s);
            case CLS, SYM, NAMED, MEM -> s;
            case ADDR -> "0x" + Long.toHexString(n);
            case RET -> s.length() <= 160 ? s : "x0";
        };
    }

    static String quote(String v) {
        StringBuilder b = new StringBuilder("\"");
        int len = Math.min(v.length(), MAX_LITERAL);
        for (int i = 0; i < len; i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                default -> {
                    if (c < 0x20) b.append(String.format("\\x%02x", (int) c));
                    else b.append(c);
                }
            }
        }
        if (v.length() > len) b.append("...");
        return b.append('"').toString();
    }
}
