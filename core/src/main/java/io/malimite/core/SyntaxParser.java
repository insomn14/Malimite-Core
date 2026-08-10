package io.malimite.core;

import io.malimite.core.antlr.CPP14Lexer;
import io.malimite.core.antlr.CPP14Parser;
import io.malimite.core.antlr.CPP14ParserBaseVisitor;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * ANTLR4-backed C++14 parser for cross-reference extraction from Ghidra decompiled output.
 * Port of Malimite's SyntaxParser.java — logging replaced with SLF4J.
 */
public class SyntaxParser {

    private static final Logger log = LoggerFactory.getLogger(SyntaxParser.class);

    private final CPP14Lexer  lexer;
    private final CPP14Parser parser;
    private final String      executableName;

    private String currentFunction = "";
    private String currentClass    = "";
    private String formattedCode   = "";

    private final List<FunctionRefResult>  funcRefs  = new ArrayList<>();
    private final List<TypeInfoResult>     typeInfos = new ArrayList<>();
    private final List<VariableRefResult>  varRefs   = new ArrayList<>();

    public SyntaxParser(String executableName) {
        this.executableName = executableName;
        this.lexer  = new CPP14Lexer(CharStreams.fromString(""));
        this.parser = new CPP14Parser(new CommonTokenStream(lexer));
        lexer.removeErrorListeners();
        parser.removeErrorListeners();
    }

    public void setContext(String functionName, String className) {
        this.currentFunction = functionName;
        this.currentClass    = className;
    }

    public void collectCrossReferences(String code) {
        if (currentFunction == null || currentClass == null) {
            log.warn("Cannot collect cross-references: missing context");
            return;
        }
        this.formattedCode = code;
        try {
            CharStream input = CharStreams.fromString(code);
            lexer.setInputStream(input);
            CommonTokenStream tokens = new CommonTokenStream(lexer);
            parser.setTokenStream(tokens);
            ParseTree tree = parser.translationUnit();
            if (tree != null) new CrossReferenceVisitor().visit(tree);
        } catch (Exception e) {
            log.debug("Cross-reference parse failed for {}.{}: {}", currentClass, currentFunction, e.getMessage());
        }
    }

    public List<FunctionRefResult>  getFunctionRefResults()  { return funcRefs; }
    public List<VariableRefResult>  getVariableRefResults()  { return varRefs; }
    public List<TypeInfoResult>     getTypeInfoResults()     { return typeInfos; }

    // ── result POJOs ──────────────────────────────────────────────────────────

    public static class FunctionRefResult {
        public final String sourceFunction;
        public final String sourceClass;
        public final String targetFunction;
        public final String targetClass;
        public final int    lineNumber;
        public final String executableName;

        public FunctionRefResult(String sourceFunction, String sourceClass,
                                 String targetFunction, String targetClass,
                                 int lineNumber, String executableName) {
            this.sourceFunction = sourceFunction;
            this.sourceClass    = sourceClass;
            this.targetFunction = targetFunction;
            this.targetClass    = targetClass;
            this.lineNumber     = lineNumber;
            this.executableName = executableName;
        }
    }

    public static class VariableRefResult {
        public final String variableName;
        public final String functionName;
        public final String className;
        public final int    lineNumber;
        public final String executableName;

        public VariableRefResult(String variableName, String functionName,
                                 String className, int lineNumber, String executableName) {
            this.variableName   = variableName;
            this.functionName   = functionName;
            this.className      = className;
            this.lineNumber     = lineNumber;
            this.executableName = executableName;
        }
    }

    public static class TypeInfoResult {
        public final String variableName;
        public final String variableType;
        public final String functionName;
        public final String className;
        public final int    lineNumber;
        public final String executableName;

        public TypeInfoResult(String variableName, String variableType,
                              String functionName, String className,
                              int lineNumber, String executableName) {
            this.variableName   = variableName;
            this.variableType   = variableType;
            this.functionName   = functionName;
            this.className      = className;
            this.lineNumber     = lineNumber;
            this.executableName = executableName;
        }
    }

    // ── ANTLR visitor ─────────────────────────────────────────────────────────

    private final class CrossReferenceVisitor extends CPP14ParserBaseVisitor<Void> {

        @Override
        public Void visitPostfixExpression(CPP14Parser.PostfixExpressionContext ctx) {
            if (ctx.getChildCount() >= 2 && ctx.getChild(1).getText().equals("(")) {
                String calledFunction = ctx.getChild(0).getText();
                String calledClass    = null;
                if (calledFunction.contains("::")) {
                    String[] parts = calledFunction.split("::");
                    calledClass    = parts[0];
                    calledFunction = parts[1];
                }
                int line = calculateActualLine(ctx.getStart().getLine());
                funcRefs.add(new FunctionRefResult(
                        currentFunction, currentClass,
                        calledFunction, calledClass != null ? calledClass : "Unknown",
                        line, executableName));
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitDeclarationStatement(CPP14Parser.DeclarationStatementContext ctx) {
            if (ctx.blockDeclaration() != null &&
                ctx.blockDeclaration().simpleDeclaration() != null) {

                CPP14Parser.SimpleDeclarationContext simpleDecl =
                        ctx.blockDeclaration().simpleDeclaration();

                String variableType = simpleDecl.declSpecifierSeq() != null
                        ? simpleDecl.declSpecifierSeq().getText() : "";

                if (simpleDecl.initDeclaratorList() != null) {
                    for (CPP14Parser.InitDeclaratorContext initDecl :
                            simpleDecl.initDeclaratorList().initDeclarator()) {
                        String variableName = initDecl.declarator().getText();
                        if (variableName.contains("="))
                            variableName = variableName.substring(0, variableName.indexOf("=")).trim();
                        int line = calculateActualLine(ctx.getStart().getLine());
                        typeInfos.add(new TypeInfoResult(variableName, variableType,
                                currentFunction, currentClass, line, executableName));
                        varRefs.add(new VariableRefResult(variableName,
                                currentFunction, currentClass, line, executableName));
                    }
                }
            }
            return visitChildren(ctx);
        }

        @Override
        public Void visitIdExpression(CPP14Parser.IdExpressionContext ctx) {
            String identifier = ctx.getText();
            int line = calculateActualLine(ctx.getStart().getLine());
            if (identifier.contains("::")) {
                String[] parts = identifier.split("::");
                funcRefs.add(new FunctionRefResult(
                        currentFunction, currentClass, null, parts[0], line, executableName));
            } else if (!isPartOfFunctionCall(ctx)) {
                varRefs.add(new VariableRefResult(
                        identifier, currentFunction, currentClass, line, executableName));
            }
            return visitChildren(ctx);
        }

        private boolean isPartOfFunctionCall(CPP14Parser.IdExpressionContext ctx) {
            ParseTree parent = ctx.getParent();
            while (parent != null) {
                if (parent instanceof CPP14Parser.PostfixExpressionContext p) {
                    return p.getChildCount() >= 2 && p.getChild(1).getText().equals("(");
                }
                parent = parent.getParent();
            }
            return false;
        }

        private int calculateActualLine(int parsedLine) {
            String[] lines = formattedCode.split("\n", parsedLine + 1);
            int actual = 0;
            for (int i = 0; i < Math.min(lines.length, parsedLine); i++) {
                actual++;
                String line = lines[i].trim();
                if (line.contains("/*")) {
                    int cur = i;
                    while (cur < lines.length && !lines[cur].contains("*/")) {
                        if (cur != i) actual++;
                        cur++;
                    }
                    if (cur < lines.length && lines[cur].contains("*/") && cur != i) actual++;
                    i = cur;
                }
            }
            return actual;
        }
    }
}
