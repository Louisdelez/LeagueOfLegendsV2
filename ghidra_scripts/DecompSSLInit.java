import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
public class DecompSSLInit extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Address addr = currentProgram.getAddressFactory().getAddress("14072c890");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        println("=== FUN_14072c890 (SSL context init) ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            String code = r.getDecompiledFunction().getC();
            // Look for verify_mode or set_verify calls
            for (String line : code.split("\n")) {
                if (line.contains("verify") || line.contains("0x01") || line.contains("VERIFY") ||
                    line.contains("SSL") || line.contains("0x88") || line.contains("callback") ||
                    line.contains("FUN_14") || line.contains("malloc") || line.contains("0x1e0")) {
                    println(line);
                }
            }
        }
        d.dispose();
    }
}
