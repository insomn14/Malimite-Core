package io.malimite.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ObfuscationSignalsTest {

    /** Same structure as the interpreters measured in a real iOS crackme: opcode byte, many constants, byte pointer advancing. */
    private static final String VM = """
            void FUN_1000047b0(void)
            {
              byte bVar2;
              byte *pbVar5;
              uint *puVar6;
              pbVar5 = &DAT_10000da4c;
            LAB_1000047f0:
              do {
                while( true ) {
                  bVar2 = *pbVar5;
                  if (0x59 < bVar2) break;
                  if (bVar2 < 0x2b) {
                    if (bVar2 == 0x1a) { pbVar5 = pbVar5 + 1; *puVar6 = *puVar6 ^ uVar1; }
                    else if (bVar2 == 0x1e) { pbVar5 = pbVar5 + 1; *puVar6 = **(uint **)puVar6; }
                    else if (bVar2 == 0x20) { pbVar5 = pbVar5 + 2; }
                  }
                  else if (bVar2 == 0x2b) { pbVar5 = pbVar5 + 1; }
                  else if (bVar2 == 0x37) { pbVar5 = pbVar5 + 1; }
                  else if (bVar2 == 0x41) { pbVar5 = pbVar5 + 3; }
                }
              } while (bVar2 != 0x5a);
              return;
            }
            """;

    /** A real Objective-C method of the same app: ordinary straight-line code. */
    private static final String BUTTON_CLICK = """
            void ViewController::buttonClick_(ID param_1,SEL param_2,ID param_3)
            {
              undefined8 uVar3;
              int iVar2;
              theTextField(param_1,(SEL)PTR_s_theTextField_10000d1e0);
              uVar3 = _objc_retainAutoreleasedReturnValue();
              iVar2 = _objc_msgSend(uVar3,PTR_s_isEqualToString__10000d1f0,uVar3);
              if (iVar2 == 0) { _objc_msgSend(uVar3,PTR_s_show_10000d208); }
              return;
            }
            """;

    private static List<SqliteStore.DecompilationResult> fns(int vm, int normal) {
        List<SqliteStore.DecompilationResult> l = new ArrayList<>();
        for (int i = 0; i < vm; i++) l.add(new SqliteStore.DecompilationResult("FUN_" + i, "Global", VM, "app"));
        for (int i = 0; i < normal; i++) l.add(new SqliteStore.DecompilationResult("m" + i, "ViewController", BUTTON_CLICK, "app"));
        return l;
    }

    @Test
    void interpreterLoopsAreRecognisedAndOrdinaryCodeIsNot() {
        assertTrue(ObfuscationSignals.looksLikeInterpreter(VM));
        assertFalse(ObfuscationSignals.looksLikeInterpreter(BUTTON_CLICK));
        assertFalse(ObfuscationSignals.looksLikeInterpreter(null));
        assertFalse(ObfuscationSignals.looksLikeInterpreter("while(true){}"));
    }

    @Test
    void aSwitchOverFewOpcodesOrWithoutAPointerWalkIsNotAnInterpreter() {
        String fewOps = VM.replace("0x37", "0x1a").replace("0x41", "0x1e").replace("0x20", "0x2b").replace("0x5a", "0x59");
        assertFalse(ObfuscationSignals.looksLikeInterpreter(fewOps), "only 4 distinct opcodes");
        String noWalk = VM.replace("pbVar5 = pbVar5 + 1;", "").replace("pbVar5 = pbVar5 + 2;", "").replace("pbVar5 = pbVar5 + 3;", "");
        assertFalse(ObfuscationSignals.looksLikeInterpreter(noWalk), "dispatch alone (a normal switch) is not enough");
    }

    @Test
    void oneOrTwoInterpretersCouldBeADecoderThreeAreAScheme() {
        assertFalse(ObfuscationSignals.analyze(fns(2, 10)).bytecodeVm());
        var r = ObfuscationSignals.analyze(fns(3, 10));
        assertTrue(r.bytecodeVm());
        assertEquals(3, r.vmFunctions());
        assertEquals(List.of("FUN_0", "FUN_1", "FUN_2"), r.samples());
        assertTrue(r.caveat().contains("not conclusive"));
        assertEquals("", ObfuscationSignals.analyze(fns(1, 5)).caveat());
        assertFalse(ObfuscationSignals.analyze(List.of()).bytecodeVm());
    }

    private static AssessmentResult absent(String id, String cat) {
        return new AssessmentResult(id, id, cat, AssessmentStatus.ABSENT, "HIGH",
                List.of("No matching signals in strings/decompilation/resources"), java.util.Map.of(), "IOS");
    }

    @Test
    void absentDetectionControlsBecomeUnknownWhenCodeRunsInsideABytecodeVm() {
        var in = List.of(absent("ASSESS-JAILBREAK-DETECTION", "DETECTION"), absent("ASSESS-ANTIDEBUG", "DETECTION"),
                absent("ASSESS-SCREEN-CAPTURE", "UI_PRIVACY"),
                absent("ASSESS-GET-TASK-ALLOW-OFF", "DETECTION"),   // a definite fact (the entitlement IS there), not a missing signal
                new AssessmentResult("ASSESS-PIE", "PIE", "HARDENING", AssessmentStatus.PRESENT, "HIGH", List.of("MH_PIE=1"),
                        java.util.Map.of(), "IOS"));
        var vm = ObfuscationSignals.analyze(fns(3, 0));
        var out = AssessmentScanner.applyBytecodeVmCaveat(in, vm, PackagePlatform.IOS);

        var byId = new java.util.HashMap<String, AssessmentResult>();
        out.forEach(r -> byId.put(r.controlId(), r));
        assertEquals(AssessmentStatus.UNKNOWN, byId.get("ASSESS-JAILBREAK-DETECTION").status());
        assertEquals("LOW", byId.get("ASSESS-JAILBREAK-DETECTION").confidence());
        assertTrue(byId.get("ASSESS-JAILBREAK-DETECTION").evidenceJoined().contains("bytecode-interpreter"));
        assertEquals(AssessmentStatus.UNKNOWN, byId.get("ASSESS-ANTIDEBUG").status());
        assertEquals(AssessmentStatus.ABSENT, byId.get("ASSESS-SCREEN-CAPTURE").status(), "UI controls are visible to static analysis");
        assertEquals(AssessmentStatus.ABSENT, byId.get("ASSESS-GET-TASK-ALLOW-OFF").status(), "facts read from the binary stay facts");
        assertEquals(AssessmentStatus.PRESENT, byId.get("ASSESS-PIE").status());
        assertEquals(AssessmentStatus.PRESENT, byId.get("ASSESS-VM-OBFUSCATION").status());
        assertEquals(in.size() + 1, out.size());
    }

    @Test
    void assessmentIsUntouchedWithoutAVm() {
        var in = List.of(absent("ASSESS-JAILBREAK-DETECTION", "DETECTION"));
        assertSame(in, AssessmentScanner.applyBytecodeVmCaveat(in, ObfuscationSignals.analyze(fns(0, 20)), PackagePlatform.IOS));
    }

    @Test
    void endToEndAbsentFindingsCarryTheCaveatOnlyForVmApps(@TempDir Path tmp) throws Exception {
        for (boolean vm : new boolean[] {true, false}) {
            try (SqliteStore store = new SqliteStore(tmp.resolve(vm + ".sqlite").toString())) {
                store.insertFunctionDecompilations(fns(vm ? 3 : 0, 3));
                new VulnerabilityScanner().scan(store, "app", PackagePlatform.IOS,
                        new LearnedRulesStore(tmp.resolve("none.json"), PackagePlatform.IOS));
                new AssessmentScanner().scan(store, "app", PackagePlatform.IOS);
                var jb = store.getVulnerabilities("app").stream().filter(v -> "MSTG-RESILIENCE-1".equals(v.get("rule_id"))).findFirst();
                assertTrue(jb.isPresent(), "the finding itself is still reported");
                assertEquals(vm, String.valueOf(jb.get().get("evidence")).contains("not conclusive"), "vm=" + vm);
                var a = store.getAssessments("app").stream().filter(x -> "ASSESS-JAILBREAK-DETECTION".equals(x.get("control_id"))).findFirst();
                assertTrue(a.isPresent());
                assertEquals(vm ? "UNKNOWN" : "ABSENT", String.valueOf(a.get().get("status")), "vm=" + vm);
            }
        }
    }
}
