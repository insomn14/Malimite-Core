package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SQLite persistence layer for analysis results.
 * Port of Malimite's SQLiteDBHandler.java — package updated, SyntaxParser types
 * now reference the local stub (Phase 3 replaces with ANTLR-backed implementation).
 */
public class SqliteStore implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SqliteStore.class);

    private final String url;
    private Connection  conn;

    public SqliteStore(String dbPath) {
        this.url = "jdbc:sqlite:" + dbPath;
        init();
    }

    // ── schema setup ──────────────────────────────────────────────────────────

    private void init() {
        try {
            conn = DriverManager.getConnection(url);
            try (Statement s = conn.createStatement()) {
                s.execute("PRAGMA journal_mode=WAL;");
                s.execute("PRAGMA synchronous=OFF;");
            }
            conn.setAutoCommit(false);
            createTables();
        } catch (SQLException e) {
            throw new RuntimeException("Failed to open SqliteStore at " + url, e);
        }
    }

    private void createTables() throws SQLException {
        try (Statement s = conn.createStatement()) {
            s.execute("""
                CREATE TABLE IF NOT EXISTS Classes (
                    ClassName      TEXT,
                    Functions      TEXT,
                    ExecutableName TEXT,
                    PRIMARY KEY (ClassName, ExecutableName)
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS Functions (
                    FunctionName      TEXT,
                    ParentClass       TEXT,
                    DecompilationCode TEXT,
                    ExecutableName    TEXT,
                    PRIMARY KEY (FunctionName, ParentClass, ExecutableName)
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS MachoStrings (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    address        TEXT,
                    value          TEXT,
                    segment        TEXT,
                    label          TEXT,
                    ExecutableName TEXT
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS ResourceStrings (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    resourceId TEXT,
                    value      TEXT,
                    type       TEXT
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS EntryPoints (
                    FunctionName   TEXT,
                    ClassName      TEXT,
                    ExecutableName TEXT,
                    PRIMARY KEY (FunctionName, ClassName, ExecutableName)
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS LlmFindings (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    FunctionName   TEXT,
                    ClassName      TEXT,
                    ExecutableName TEXT,
                    Mode           TEXT,
                    Finding        TEXT,
                    CacheKey       TEXT,
                    CreatedAt      INTEGER
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS FunctionReferences (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    sourceFunction TEXT,
                    sourceClass    TEXT,
                    targetFunction TEXT,
                    targetClass    TEXT,
                    lineNumber     INTEGER,
                    ExecutableName TEXT
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS LocalVariableReferences (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    variableName      TEXT,
                    containingFunction TEXT,
                    containingClass   TEXT,
                    lineNumber        INTEGER,
                    ExecutableName    TEXT
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS TypeInformation (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    variableName   TEXT,
                    variableType   TEXT,
                    functionName   TEXT,
                    className      TEXT,
                    lineNumber     INTEGER,
                    ExecutableName TEXT
                )""");
            s.execute("""
                CREATE TABLE IF NOT EXISTS Vulnerabilities (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    RuleId         TEXT,
                    Title          TEXT,
                    Category       TEXT,
                    Severity       TEXT,
                    CvssScore      REAL,
                    Cwe            TEXT,
                    Description    TEXT,
                    AffectedType   TEXT,
                    AffectedName   TEXT,
                    Evidence       TEXT,
                    EvidenceLocation TEXT,
                    PocSteps       TEXT,
                    Remediation    TEXT,
                    ReferenceUrl   TEXT,
                    ExecutableName TEXT,
                    CreatedAt      INTEGER,
                    Status            TEXT DEFAULT 'open',
                    OverrideSeverity  TEXT,
                    OverrideCvssScore REAL,
                    OverrideNote      TEXT,
                    UpdatedAt         INTEGER
                )""");
            // Safe-add columns for databases created before the triage feature
            addColumnIfMissing(s, "Vulnerabilities", "Status",            "TEXT DEFAULT 'open'");
            addColumnIfMissing(s, "Vulnerabilities", "OverrideSeverity",  "TEXT");
            addColumnIfMissing(s, "Vulnerabilities", "OverrideCvssScore", "REAL");
            addColumnIfMissing(s, "Vulnerabilities", "OverrideNote",      "TEXT");
            addColumnIfMissing(s, "Vulnerabilities", "UpdatedAt",         "INTEGER");
            // Decompiler origin: JADX (Android Java) vs GHIDRA (iOS Mach-O / Android .so)
            addColumnIfMissing(s, "Functions", "Origin", "TEXT DEFAULT 'GHIDRA'");
            s.execute("""
                CREATE TABLE IF NOT EXISTS Assessments (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    ControlId      TEXT,
                    Title          TEXT,
                    Category       TEXT,
                    Status         TEXT,
                    Confidence     TEXT,
                    Evidence       TEXT,
                    Detail         TEXT,
                    Platform       TEXT,
                    ExecutableName TEXT,
                    CreatedAt      INTEGER
                )""");
            conn.commit();
        }
    }

    /** Adds a column with {@code ALTER TABLE ... ADD COLUMN} only if it isn't already present. */
    private void addColumnIfMissing(Statement s, String table, String column, String type) {
        try (ResultSet rs = s.executeQuery("PRAGMA table_info(" + table + ")")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) return;
            }
        } catch (SQLException e) {
            log.warn("PRAGMA table_info({}) failed: {}", table, e.getMessage());
            return;
        }
        try {
            s.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + type);
        } catch (SQLException e) {
            log.warn("ALTER TABLE {} ADD COLUMN {}: {}", table, column, e.getMessage());
        }
    }

    // ── write operations ──────────────────────────────────────────────────────

    public void insertClass(String className, String functionsJson, String executableName) {
        String sql = """
                INSERT INTO Classes(ClassName, Functions, ExecutableName)
                VALUES(?,?,?)
                ON CONFLICT(ClassName, ExecutableName) DO UPDATE SET Functions=excluded.Functions
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, className);
            p.setString(2, functionsJson);
            p.setString(3, executableName);
            p.executeUpdate();
        } catch (SQLException e) {
            log.error("insertClass failed", e);
        }
    }

    /**
     * @param origin {@code JADX} or {@code GHIDRA}; null/blank defaults to {@code GHIDRA}
     */
    public record DecompilationResult(
            String functionName,
            String className,
            String decompiledCode,
            String executableName,
            String origin) {
        public DecompilationResult(String functionName, String className,
                                   String decompiledCode, String executableName) {
            this(functionName, className, decompiledCode, executableName, "GHIDRA");
        }

        public String resolvedOrigin() {
            if (origin == null || origin.isBlank()) return "GHIDRA";
            return origin.trim().toUpperCase();
        }
    }

    public void insertFunctionDecompilations(List<DecompilationResult> results) {
        String sql = """
                INSERT INTO Functions(FunctionName, ParentClass, DecompilationCode, ExecutableName, Origin)
                VALUES(?,?,?,?,?)
                ON CONFLICT(FunctionName, ParentClass, ExecutableName)
                DO UPDATE SET DecompilationCode=excluded.DecompilationCode,
                              Origin=excluded.Origin
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            for (DecompilationResult r : results) {
                p.setString(1, r.functionName());
                p.setString(2, r.className());
                p.setString(3, r.decompiledCode());
                p.setString(4, r.executableName());
                p.setString(5, r.resolvedOrigin());
                p.addBatch();
            }
            p.executeBatch();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertFunctionDecompilations failed", e);
        }
    }

    public void insertMachoString(String address, String value, String segment,
                                   String label, String executableName) {
        String sql = "INSERT INTO MachoStrings(address,value,segment,label,ExecutableName) VALUES(?,?,?,?,?)";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, address); p.setString(2, value);
            p.setString(3, segment); p.setString(4, label);
            p.setString(5, executableName);
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertMachoString failed", e);
        }
    }

    public void insertFunctionReferences(List<SyntaxParser.FunctionRefResult> refs) {
        if (refs.isEmpty()) return;
        String sql = """
                INSERT OR IGNORE INTO FunctionReferences
                (sourceFunction,sourceClass,targetFunction,targetClass,lineNumber,ExecutableName)
                VALUES(?,?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            for (var r : refs) {
                p.setString(1, r.sourceFunction); p.setString(2, r.sourceClass);
                p.setString(3, r.targetFunction); p.setString(4, r.targetClass);
                p.setInt(5, r.lineNumber);         p.setString(6, r.executableName);
                p.addBatch();
            }
            p.executeBatch(); conn.commit();
        } catch (SQLException e) {
            log.error("insertFunctionReferences failed", e);
        }
    }

    public void insertLocalVariableReferences(List<SyntaxParser.VariableRefResult> refs) {
        if (refs.isEmpty()) return;
        String sql = """
                INSERT OR IGNORE INTO LocalVariableReferences
                (variableName,containingFunction,containingClass,lineNumber,ExecutableName)
                VALUES(?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            for (var r : refs) {
                p.setString(1, r.variableName);   p.setString(2, r.functionName);
                p.setString(3, r.className);       p.setInt(4, r.lineNumber);
                p.setString(5, r.executableName);
                p.addBatch();
            }
            p.executeBatch(); conn.commit();
        } catch (SQLException e) {
            log.error("insertLocalVariableReferences failed", e);
        }
    }

    public void insertTypeInformations(List<SyntaxParser.TypeInfoResult> infos) {
        if (infos.isEmpty()) return;
        String sql = """
                INSERT INTO TypeInformation
                (variableName,variableType,functionName,className,lineNumber,ExecutableName)
                VALUES(?,?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            for (var t : infos) {
                p.setString(1, t.variableName); p.setString(2, t.variableType);
                p.setString(3, t.functionName); p.setString(4, t.className);
                p.setInt(5, t.lineNumber);       p.setString(6, t.executableName);
                p.addBatch();
            }
            p.executeBatch(); conn.commit();
        } catch (SQLException e) {
            log.error("insertTypeInformations failed", e);
        }
    }

    // ── read operations ───────────────────────────────────────────────────────

    public Map<String, List<String>> getAllClassesAndFunctions() {
        Map<String, List<String>> out = new HashMap<>();
        try (Statement s = conn.createStatement();
             ResultSet rs = s.executeQuery("SELECT ClassName, Functions FROM Classes")) {
            while (rs.next())
                out.put(rs.getString("ClassName"), parseFunctionList(rs.getString("Functions")));
        } catch (SQLException e) {
            log.error("getAllClassesAndFunctions failed", e);
        }
        return out;
    }

    public Map<String, List<String>> getClassesAndFunctions(String executableName) {
        Map<String, List<String>> out = new HashMap<>();
        String sql = "SELECT ClassName, Functions FROM Classes WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next())
                    out.put(rs.getString("ClassName"), parseFunctionList(rs.getString("Functions")));
            }
        } catch (SQLException e) {
            log.error("getClassesAndFunctions failed", e);
        }
        return out;
    }

    public int getFunctionCount(String executableName) {
        String sql = "SELECT COUNT(*) FROM Functions WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            log.error("getFunctionCount failed", e);
        }
        return 0;
    }

    public int getStringCount(String executableName) {
        String sql = "SELECT COUNT(*) FROM MachoStrings WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            log.error("getStringCount failed", e);
        }
        return 0;
    }

    public List<Map<String, String>> getMachoStrings() {
        List<Map<String, String>> out = new ArrayList<>();
        try (Statement s = conn.createStatement();
             ResultSet rs = s.executeQuery("SELECT address,value,segment,label,ExecutableName FROM MachoStrings")) {
            while (rs.next()) {
                Map<String, String> row = new HashMap<>();
                row.put("address", rs.getString("address"));
                row.put("value",   rs.getString("value"));
                row.put("segment", rs.getString("segment"));
                row.put("label",   rs.getString("label"));
                row.put("ExecutableName", rs.getString("ExecutableName"));
                out.add(row);
            }
        } catch (SQLException e) {
            log.error("getMachoStrings failed", e);
        }
        return out;
    }

    public List<Map<String, String>> getMachoStrings(String executableName, int limit) {
        List<Map<String, String>> out = new ArrayList<>();
        String sql = "SELECT address,value,segment,label FROM MachoStrings WHERE ExecutableName=? LIMIT ?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            p.setInt(2, limit);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> row = new HashMap<>();
                    row.put("address", rs.getString("address"));
                    row.put("value",   rs.getString("value"));
                    row.put("segment", rs.getString("segment"));
                    row.put("label",   rs.getString("label"));
                    out.add(row);
                }
            }
        } catch (SQLException e) {
            log.error("getMachoStrings(executableName,limit) failed", e);
        }
        return out;
    }

    public List<Map<String, String>> getFunctionsByClass(String className, String executableName,
                                                          int offset, int limit) {
        List<Map<String, String>> out = new ArrayList<>();
        String sql = """
                SELECT FunctionName, DecompilationCode FROM Functions
                WHERE ParentClass=? AND ExecutableName=?
                LIMIT ? OFFSET ?
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, className);
            p.setString(2, executableName);
            p.setInt(3, limit);
            p.setInt(4, offset);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> row = new HashMap<>();
                    row.put("functionName",    rs.getString("FunctionName"));
                    row.put("decompiledCode",  rs.getString("DecompilationCode"));
                    out.add(row);
                }
            }
        } catch (SQLException e) {
            log.error("getFunctionsByClass failed", e);
        }
        return out;
    }

    public String getFunctionDecompilation(String functionName, String className, String executableName) {
        String sql = "SELECT DecompilationCode FROM Functions WHERE FunctionName=? AND ParentClass=? AND ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, functionName); p.setString(2, className); p.setString(3, executableName);
            try (ResultSet rs = p.executeQuery()) {
                if (rs.next()) return rs.getString("DecompilationCode");
            }
        } catch (SQLException e) {
            log.error("getFunctionDecompilation failed", e);
        }
        return null;
    }

    public List<DecompilationResult> getAllDecompiledFunctions(String executableName) {
        List<DecompilationResult> out = new ArrayList<>();
        String sql = "SELECT FunctionName, ParentClass, DecompilationCode, Origin FROM Functions WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    String origin = rs.getString("Origin");
                    out.add(new DecompilationResult(
                            rs.getString("FunctionName"),
                            rs.getString("ParentClass"),
                            rs.getString("DecompilationCode"),
                            executableName,
                            origin == null || origin.isBlank() ? "GHIDRA" : origin));
                }
            }
        } catch (SQLException e) {
            log.error("getAllDecompiledFunctions failed", e);
        }
        return out;
    }

    public void insertLlmFinding(String functionName, String className, String executableName,
                                  String mode, String finding, String cacheKey) {
        String sql = """
                INSERT INTO LlmFindings(FunctionName,ClassName,ExecutableName,Mode,Finding,CacheKey,CreatedAt)
                VALUES(?,?,?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, functionName); p.setString(2, className);
            p.setString(3, executableName); p.setString(4, mode);
            p.setString(5, finding); p.setString(6, cacheKey);
            p.setLong(7, System.currentTimeMillis());
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertLlmFinding failed", e);
        }
    }

    public List<Map<String, String>> getLlmFindings(String executableName) {
        List<Map<String, String>> out = new ArrayList<>();
        String sql = "SELECT FunctionName,ClassName,Mode,Finding FROM LlmFindings WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    Map<String, String> row = new HashMap<>();
                    row.put("functionName", rs.getString("FunctionName"));
                    row.put("className",    rs.getString("ClassName"));
                    row.put("mode",         rs.getString("Mode"));
                    row.put("finding",      rs.getString("Finding"));
                    out.add(row);
                }
            }
        } catch (SQLException e) {
            log.error("getLlmFindings failed", e);
        }
        return out;
    }

    public List<Map<String, String>> getResourceStrings() {
        List<Map<String, String>> out = new ArrayList<>();
        try (Statement s = conn.createStatement();
             ResultSet rs = s.executeQuery("SELECT resourceId,value,type FROM ResourceStrings")) {
            while (rs.next()) {
                Map<String, String> row = new HashMap<>();
                row.put("resourceId", rs.getString("resourceId"));
                row.put("value",      rs.getString("value"));
                row.put("type",       rs.getString("type"));
                out.add(row);
            }
        } catch (SQLException e) {
            log.error("getResourceStrings failed", e);
        }
        return out;
    }

    public void insertResourceString(String resourceId, String value, String type) {
        String sql = "INSERT INTO ResourceStrings(resourceId,value,type) VALUES(?,?,?)";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, resourceId); p.setString(2, value); p.setString(3, type);
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertResourceString failed", e);
        }
    }

    public void insertEntryPoint(String functionName, String className, String executableName) {
        String sql = """
                INSERT OR IGNORE INTO EntryPoints(FunctionName,ClassName,ExecutableName)
                VALUES(?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, functionName); p.setString(2, className); p.setString(3, executableName);
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertEntryPoint failed", e);
        }
    }

    public List<String> getEntryPoints(String executableName) {
        List<String> out = new ArrayList<>();
        String sql = "SELECT ClassName, FunctionName FROM EntryPoints WHERE ExecutableName=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next())
                    out.add(rs.getString("ClassName") + "." + rs.getString("FunctionName"));
            }
        } catch (SQLException e) {
            log.error("getEntryPoints failed", e);
        }
        return out;
    }

    // ── vulnerabilities ───────────────────────────────────────────────────────

    public void insertVulnerability(Vulnerability v, String executableName) {
        String sql = """
                INSERT INTO Vulnerabilities(
                    RuleId, Title, Category, Severity, CvssScore, Cwe, Description,
                    AffectedType, AffectedName, Evidence, EvidenceLocation,
                    PocSteps, Remediation, ReferenceUrl, ExecutableName, CreatedAt)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, v.ruleId());
            p.setString(2, v.title());
            p.setString(3, v.category());
            p.setString(4, v.severity());
            p.setDouble(5, v.cvssScore());
            p.setString(6, v.cwe());
            p.setString(7, v.description());
            p.setString(8, v.affectedType());
            p.setString(9, v.affectedName());
            p.setString(10, v.evidence());
            p.setString(11, v.evidenceLocation());
            p.setString(12, v.pocSteps());
            p.setString(13, v.remediation());
            p.setString(14, v.referenceUrl());
            p.setString(15, executableName);
            p.setLong(16, System.currentTimeMillis());
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertVulnerability failed", e);
        }
    }

    public void clearVulnerabilities(String executableName) {
        try (PreparedStatement p = conn.prepareStatement(
                "DELETE FROM Vulnerabilities WHERE ExecutableName=?")) {
            p.setString(1, executableName);
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("clearVulnerabilities failed", e);
        }
    }

    public List<Map<String, Object>> getVulnerabilities(String executableName) {
        List<Map<String, Object>> out = new ArrayList<>();
        // Sort:
        //   1. Active findings before suppressed (false_positive / fixed at the bottom)
        //   2. Effective severity (CRITICAL → HIGH → MEDIUM → LOW → INFO)
        //   3. Effective CVSS descending
        //   4. RuleId for stability
        String sql = """
                SELECT id, RuleId, Title, Category, Severity, CvssScore, Cwe, Description,
                       AffectedType, AffectedName, Evidence, EvidenceLocation,
                       PocSteps, Remediation, ReferenceUrl,
                       Status, OverrideSeverity, OverrideCvssScore, OverrideNote, UpdatedAt
                FROM Vulnerabilities WHERE ExecutableName=?
                ORDER BY
                    CASE WHEN COALESCE(Status,'open') IN ('false_positive','fixed') THEN 1 ELSE 0 END,
                    CASE UPPER(COALESCE(OverrideSeverity, Severity, ''))
                        WHEN 'CRITICAL' THEN 0
                        WHEN 'HIGH'     THEN 1
                        WHEN 'MEDIUM'   THEN 2
                        WHEN 'LOW'      THEN 3
                        WHEN 'INFO'     THEN 4
                        ELSE 5
                    END,
                    COALESCE(OverrideCvssScore, CvssScore) DESC,
                    RuleId
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> row = new HashMap<>();
                    row.put("id",                rs.getLong("id"));
                    row.put("rule_id",           rs.getString("RuleId"));
                    row.put("title",             rs.getString("Title"));
                    row.put("category",          rs.getString("Category"));
                    row.put("severity",          rs.getString("Severity"));
                    row.put("cvss_score",        rs.getDouble("CvssScore"));
                    row.put("cwe",               rs.getString("Cwe"));
                    row.put("description",       rs.getString("Description"));
                    row.put("affected_type",     rs.getString("AffectedType"));
                    row.put("affected_name",     rs.getString("AffectedName"));
                    row.put("evidence",          rs.getString("Evidence"));
                    row.put("evidence_location", rs.getString("EvidenceLocation"));
                    row.put("poc_steps",         rs.getString("PocSteps"));
                    row.put("remediation",       rs.getString("Remediation"));
                    row.put("reference_url",     rs.getString("ReferenceUrl"));
                    String status = rs.getString("Status");
                    row.put("status",            status == null ? "open" : status);
                    row.put("override_severity", rs.getString("OverrideSeverity"));
                    double ocvss = rs.getDouble("OverrideCvssScore");
                    row.put("override_cvss_score", rs.wasNull() ? null : ocvss);
                    row.put("override_note",     rs.getString("OverrideNote"));
                    long updated = rs.getLong("UpdatedAt");
                    row.put("updated_at",        rs.wasNull() ? null : updated);
                    out.add(row);
                }
            }
        } catch (SQLException e) {
            log.error("getVulnerabilities failed", e);
        }
        return out;
    }

    /**
     * Updates triage fields for a single vulnerability row.
     * Pass {@code null} for fields that should not change. Returns true if a row was updated.
     */
    public boolean updateVulnerabilityTriage(long id, String status,
                                              String overrideSeverity,
                                              Double overrideCvssScore,
                                              String overrideNote) {
        List<String> sets = new ArrayList<>();
        List<Object> args = new ArrayList<>();
        if (status != null)            { sets.add("Status=?");            args.add(status); }
        if (overrideSeverity != null)  { sets.add("OverrideSeverity=?");  args.add(overrideSeverity); }
        if (overrideCvssScore != null) { sets.add("OverrideCvssScore=?"); args.add(overrideCvssScore); }
        if (overrideNote != null)      { sets.add("OverrideNote=?");      args.add(overrideNote); }
        sets.add("UpdatedAt=?"); args.add(System.currentTimeMillis());

        String sql = "UPDATE Vulnerabilities SET " + String.join(",", sets) + " WHERE id=?";
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            int i = 1;
            for (Object a : args) {
                if (a instanceof String s) p.setString(i, s);
                else if (a instanceof Double d) p.setDouble(i, d);
                else if (a instanceof Long l) p.setLong(i, l);
                i++;
            }
            p.setLong(i, id);
            int rows = p.executeUpdate();
            conn.commit();
            return rows > 0;
        } catch (SQLException e) {
            log.error("updateVulnerabilityTriage failed", e);
            return false;
        }
    }

    // ── assessments (security controls inventory) ─────────────────────────────

    public void clearAssessments(String executableName) {
        try (PreparedStatement p = conn.prepareStatement(
                "DELETE FROM Assessments WHERE ExecutableName=?")) {
            p.setString(1, executableName);
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("clearAssessments failed", e);
        }
    }

    public void insertAssessment(AssessmentResult a, String executableName) {
        String sql = """
                INSERT INTO Assessments(
                    ControlId, Title, Category, Status, Confidence,
                    Evidence, Detail, Platform, ExecutableName, CreatedAt)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, a.controlId());
            p.setString(2, a.title());
            p.setString(3, a.category());
            p.setString(4, a.status().name());
            p.setString(5, a.confidence());
            p.setString(6, a.evidenceJoined());
            p.setString(7, a.detailJoined());
            p.setString(8, a.platform());
            p.setString(9, executableName);
            p.setLong(10, System.currentTimeMillis());
            p.executeUpdate();
            conn.commit();
        } catch (SQLException e) {
            log.error("insertAssessment failed", e);
        }
    }

    public List<Map<String, Object>> getAssessments(String executableName) {
        List<Map<String, Object>> out = new ArrayList<>();
        String sql = """
                SELECT id, ControlId, Title, Category, Status, Confidence,
                       Evidence, Detail, Platform, CreatedAt
                FROM Assessments WHERE ExecutableName=?
                ORDER BY Category, ControlId
                """;
        try (PreparedStatement p = conn.prepareStatement(sql)) {
            p.setString(1, executableName);
            try (ResultSet rs = p.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> row = new HashMap<>();
                    row.put("id", rs.getLong("id"));
                    row.put("control_id", rs.getString("ControlId"));
                    row.put("title", rs.getString("Title"));
                    row.put("category", rs.getString("Category"));
                    row.put("status", rs.getString("Status"));
                    row.put("confidence", rs.getString("Confidence"));
                    row.put("evidence", rs.getString("Evidence"));
                    row.put("detail", rs.getString("Detail"));
                    row.put("platform", rs.getString("Platform"));
                    row.put("created_at", rs.getLong("CreatedAt"));
                    out.add(row);
                }
            }
        } catch (SQLException e) {
            log.error("getAssessments failed", e);
        }
        return out;
    }

    // ── lifecycle ─────────────────────────────────────────────────────────────

    @Override
    public void close() {
        try { if (conn != null && !conn.isClosed()) conn.close(); }
        catch (SQLException e) { log.warn("Error closing SqliteStore", e); }
    }

    // ── util ──────────────────────────────────────────────────────────────────

    private static List<String> parseFunctionList(String json) {
        List<String> out = new ArrayList<>();
        if (json == null || json.isBlank()) return out;
        // Minimal JSON array parser — avoids pulling in another dep
        String stripped = json.trim();
        if (stripped.startsWith("[")) stripped = stripped.substring(1);
        if (stripped.endsWith("]")) stripped = stripped.substring(0, stripped.length() - 1);
        for (String part : stripped.split(",")) {
            String s = part.trim().replaceAll("^\"|\"$", "");
            if (!s.isBlank()) out.add(s);
        }
        return out;
    }
}
