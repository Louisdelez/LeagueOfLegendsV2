import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;

public class DecompAt58B099 extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // recvfrom return address is +0x58B099, so the call is at +0x58B094 (5-byte CALL instruction)
        // Target address in Ghidra: 0x14058B099
        Address targetAddr = currentProgram.getAddressFactory().getAddress("14058b099");

        // Find the function containing this address
        Function func = currentProgram.getFunctionManager().getFunctionContaining(targetAddr);

        if (func != null) {
            println("=== FUNCTION CONTAINING recvfrom call ===");
            println("Function: " + func.getName() + " at " + func.getEntryPoint());
            println("Size: " + func.getBody().getNumAddresses());
            println("recvfrom call at: 14058b099 (offset +" +
                    (targetAddr.getOffset() - func.getEntryPoint().getOffset()) + " into function)");

            DecompileResults result = decomp.decompileFunction(func, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                for (String line : lines) {
                    println(line);
                }
            }
        } else {
            println("No function contains 14058b099!");
            // List all functions in the area 0x58A000-0x58C000
            println("Functions near 0x58B000:");
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(
                currentProgram.getAddressFactory().getAddress("14058a000"), true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getEntryPoint().getOffset() > 0x14058c000L) break;
                long end = f.getEntryPoint().getOffset() + f.getBody().getNumAddresses();
                boolean contains = (0x14058b099L >= f.getEntryPoint().getOffset() && 0x14058b099L < end);
                println("  " + f.getEntryPoint() + " " + f.getName() + " size=" +
                        f.getBody().getNumAddresses() + (contains ? " *** CONTAINS TARGET ***" : ""));
            }

            // Also check if there's code at the target but no function defined
            println("\nInstruction at 14058b099: " +
                    currentProgram.getListing().getInstructionAt(targetAddr));
            // Check a few bytes before (the CALL instruction)
            for (int i = -10; i <= 5; i++) {
                Address a = currentProgram.getAddressFactory().getAddress(
                    String.format("%x", 0x14058b099L + i));
                var inst = currentProgram.getListing().getInstructionAt(a);
                if (inst != null) {
                    println("  " + a + ": " + inst);
                }
            }
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
