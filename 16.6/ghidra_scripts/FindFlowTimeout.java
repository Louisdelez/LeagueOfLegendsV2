import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
public class FindFlowTimeout extends GhidraScript {
    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        // Find "Timeout waiting to connect to" string and its xrefs
        byte[] pattern = "Timeout waiting to connect to".getBytes("UTF-8");
        Address strAddr = mem.findBytes(currentProgram.getMinAddress(), pattern, null, true, monitor);
        if (strAddr == null) { println("String not found!"); return; }
        println("String at: " + strAddr);
        
        // Search for LEA instructions that reference this address (within .text)
        // The RVA of the string relative to image base
        long strRVA = strAddr.getOffset() - 0x140000000L;
        println("String RVA: 0x" + Long.toHexString(strRVA));
        
        // Search .text for the 4-byte offset that would reference this string via LEA
        // In x64, LEA REG,[RIP+offset] encodes as: opcode modrm disp32
        // The displacement = target - (instruction_addr + instruction_length)
        // We need to search for this displacement value
        
        // Alternative: search for the string bytes directly referenced
        // Look for any reference to the string address
        var refs = getReferencesTo(strAddr);
        println("References to string: " + refs.length);
        for (var ref : refs) {
            println("  From: " + ref.getFromAddress() + " type=" + ref.getReferenceType());
            // Decompile the function containing this reference
            Function fn = getFunctionContaining(ref.getFromAddress());
            if (fn != null) {
                println("  In function: " + fn.getName() + " at " + fn.getEntryPoint() + " size=" + fn.getBody().getNumAddresses());
                // Decompile to find the condition
                DecompInterface d = new DecompInterface();
                d.openProgram(currentProgram);
                DecompileResults r = d.decompileFunction(fn, 60, monitor);
                if (r.decompileCompleted()) {
                    String code = r.getDecompiledFunction().getC();
                    // Find lines containing "Timeout" or "connect"
                    for (String line : code.split("\n")) {
                        if (line.contains("Timeout") || line.contains("timeout") || 
                            line.contains("connect") || line.contains("FLOW") ||
                            line.contains("if (") || line.contains("while")) {
                            println("    " + line.trim());
                        }
                    }
                }
                d.dispose();
            }
        }
    }
}
