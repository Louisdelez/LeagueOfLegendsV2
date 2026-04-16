import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.address.Address;
public class DecompSendPath extends GhidraScript {
    public void run() throws Exception {
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        // NET_58e860 is the send loop containing both FUN_14058ef90 and sendto
        // Let's look at the FULL NET_58e860 for any CFB encryption call between them
        Address addr = currentProgram.getAddressFactory().getAddress("14058e860");
        Function f = currentProgram.getFunctionManager().getFunctionAt(addr);
        if (f == null) { println("NO FUNC"); return; }
        println("=== NET_58e860 size=" + f.getBody().getNumAddresses() + " ===");
        DecompileResults r = d.decompileFunction(f, 120, monitor);
        if (r.decompileCompleted()) {
            String code = r.getDecompiledFunction().getC();
            // Search for CFB/encryption related calls
            for (String line : code.split("\n")) {
                if (line.contains("FUN_1410f") || line.contains("sendto") || 
                    line.contains("FUN_14058ef90") || line.contains("encrypt") ||
                    line.contains("cfb") || line.contains("FUN_14058e") ||
                    line.contains("1418dfd") || line.contains("crypt")) {
                    println("  " + line.trim());
                }
            }
            println("\n=== FULL CODE ===");
            for (String line : code.split("\n")) println(line);
        }
        d.dispose();
    }
}
