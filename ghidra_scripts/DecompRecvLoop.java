import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompRecvLoop extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // FUN_14058a4f0 is the big function (2640B) near the recvfrom call
        // The recvfrom CALL is at 14058b093, return to 14058b099
        // This is likely inside FUN_14058a4f0 or a sub-function

        // First, create a function at the code containing recvfrom
        // The gap is from 14058AF20 to 14058B250
        // Let's try to create a function at 14058AF20 (after FUN_14058a4f0)
        Address gapStart = currentProgram.getAddressFactory().getAddress("14058af20");
        Function gapFunc = currentProgram.getFunctionManager().getFunctionAt(gapStart);
        if (gapFunc == null) {
            println("Creating function at 14058af20...");
            try {
                gapFunc = createFunction(gapStart, "RECV_LOOP_14058af20");
                println("Created: " + gapFunc.getName() + " size=" + gapFunc.getBody().getNumAddresses());
            } catch (Exception e) {
                println("Failed to create: " + e.getMessage());
            }
        }

        // Decompile it if found
        if (gapFunc != null) {
            println("=== RECV LOOP at " + gapFunc.getEntryPoint() + " ===");
            DecompileResults result = decomp.decompileFunction(gapFunc, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) {
                    println(line);
                }
            }
        }

        // Also decompile FUN_14058a4f0 (the big function before)
        Address bigFuncAddr = currentProgram.getAddressFactory().getAddress("14058a4f0");
        Function bigFunc = currentProgram.getFunctionManager().getFunctionAt(bigFuncAddr);
        if (bigFunc != null) {
            println("\n=== BIG FUNCTION: " + bigFunc.getName() + " ===");
            DecompileResults result = decomp.decompileFunction(bigFunc, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                // Show only lines related to recv/send/crypto/session
                for (String line : lines) {
                    println(line);
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
