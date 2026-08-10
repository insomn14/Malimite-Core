package io.malimite.core.antlr;

import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.TokenStream;

public abstract class CPP14ParserBase extends Parser {
    public CPP14ParserBase(TokenStream input) {
        super(input);
    }

    public boolean IsPureSpecifierAllowed() {
        return true;
    }
}
