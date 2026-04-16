//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

/**
 * FindOpcodeTable3 - Trace from FUN_14057dd10/dec0 to the actual game message parsers
 *
 * Flow discovered:
 *   FUN_14057dce0 -> FUN_14056e310 (queue)
 *   FUN_14057dd10 -> FUN_14057d4c0 (read framing: 0x02 + len + data + 0x18)
 *                 -> FUN_14058ded0, FUN_14058d960 (message parsers)
 *   FUN_14057dec0 -> FUN_14057d4c0 -> FUN_14058d350 (message parser)
 *
 * These parsers (14058d350, 14058d960, 14058ded0) likely read the opcode and dispatch.
 */
public class FindOpcodeTable3 extends GhidraScript {

    private DecompInterface decomp;

    @Override
    public void run() throws Exception {
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Decompile the three candidate message parsers
        println("=== FUN_14058d350 (41 MOVZX, 1545 bytes) - Message Parser A ===");
        decompFull("14058d350", 250);

        println("\n=== FUN_14058d960 (36 MOVZX, 1384 bytes) - Message Parser B ===");
        decompFull("14058d960", 250);

        println("\n=== FUN_14058ded0 (30 MOVZX, 1177 bytes) - Message Parser C ===");
        decompFull("14058ded0", 250);

        // Also decompile FUN_14058edf0 (24 MOVZX) and FUN_14058ef90 (17 MOVZX)
        println("\n=== FUN_14058edf0 (24 MOVZX, 407 bytes) - Message Parser D ===");
        decompFull("14058edf0", 150);

        println("\n=== FUN_14058ef90 (17 MOVZX, 516 bytes) - Message Parser E ===");
        decompFull("14058ef90", 150);

        // Decompile FUN_14057dd10 fully to see the dispatch logic
        println("\n=== FUN_14057dd10 - Dispatch after framing (full) ===");
        decompFull("14057dd10", 150);

        // Decompile FUN_14057dec0 fully
        println("\n=== FUN_14057dec0 - Dispatch after framing (full) ===");
        decompFull("14057dec0", 150);

        // Also check FUN_14057e7f0 which has multiple vtable jumps
        println("\n=== FUN_14057e7f0 - vtable dispatch (JMP [RAX+offset]) ===");
        decompFull("14057e7f0", 150);

        println("\n=== DONE ===");
        decomp.dispose();
    }

    private void decompFull(String hexAddr, int maxLines) {
        Address a = currentProgram.getAddressFactory().getAddress(hexAddr);
        Function f = currentProgram.getFunctionManager().getFunctionAt(a);
        if (f == null) f = currentProgram.getFunctionManager().getFunctionContaining(a);
        if (f == null) { println("No function at " + hexAddr); return; }
        println(f.getName() + " at " + f.getEntryPoint() + " size=" + f.getBody().getNumAddresses());
        try {
            DecompileResults r = decomp.decompileFunction(f, 300, monitor);
            if (r.decompileCompleted()) {
                String code = r.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                for (int i = 0; i < Math.min(maxLines, lines.length); i++) println("  " + lines[i]);
                if (lines.length > maxLines) println("  ... (" + (lines.length - maxLines) + " more lines)");

                // Highlight switch/case and byte read patterns
                boolean hasSwitch = code.contains("switch");
                boolean hasCaseHex = code.contains("case 0x");
                int caseCount = 0;
                for (String line : lines) if (line.trim().startsWith("case ")) caseCount++;
                if (hasSwitch || caseCount > 0)
                    println("  >>> SWITCH DETECTED: " + caseCount + " cases");

                // Look for byte[0] reads - first byte of buffer
                if (code.contains("[0]") || code.contains("*param") || code.contains("*(byte *)") ||
                    code.contains("*(char *)") || code.contains("*(undefined *)"))
                    println("  >>> Reads first byte from buffer");
            }
        } catch (Exception e) { println("  Error: " + e.getMessage()); }
    }
}
