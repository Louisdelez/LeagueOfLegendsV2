import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;

public class DecompRecvHandler extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Decompile functions near the send loop that could be receive handlers
        String[] addrs = {
            "14058e370", // 498B - before send loop
            "14058e580", // 728B - before send loop (likely receive)
            "14058edf0", // 407B - between send loop and encryptor
            "14058f420", // 750B - large, after encryptor
            "14058f8f0", // 538B - after encryptor
        };

        for (String addrStr : addrs) {
            Address addr = currentProgram.getAddressFactory().getAddress(addrStr);
            Function func = currentProgram.getFunctionManager().getFunctionAt(addr);
            if (func == null) {
                println("No function at " + addrStr);
                continue;
            }

            println("\n=== " + func.getName() + " at " + addrStr + " ===");

            DecompileResults result = decomp.decompileFunction(func, 120, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("Lines: " + lines.length);
                // Print all lines for analysis
                for (String line : lines) {
                    println(line);
                }
            }
        }

        println("\n=== ALL DONE ===");
        decomp.dispose();
    }
}
