//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class FindQueueWrite2 extends GhidraScript {
    public void run() throws Exception {
        // Search ALL instructions that write to offset 0xD0 from a register
        // The enqueue increments *(param + 0xD0) 
        // In assembly: INC/ADD [reg + 0xD0] or MOV [reg + 0xD0], value
        
        println("=== Searching for writes to +0xD0 ===");
        InstructionIterator iter = currentProgram.getListing().getInstructions(true);
        java.util.Set<String> seen = new java.util.HashSet<>();
        int count = 0;
        
        while (iter.hasNext() && count < 20) {
            Instruction inst = iter.next();
            String mnemonic = inst.getMnemonicString();
            String instStr = inst.toString();
            
            // Look for writes to [reg + 0xd0]: MOV, ADD, INC, XADD
            if ((mnemonic.equals("MOV") || mnemonic.equals("ADD") || mnemonic.equals("INC") || 
                 mnemonic.equals("XADD") || mnemonic.equals("LEA")) &&
                instStr.contains("0xd0]") && !instStr.contains("0xd0],0x")) {
                
                // Check if this looks like incrementing a counter
                // Skip LEA and reads
                if (mnemonic.equals("LEA")) continue;
                
                // Check if it's a WRITE (destination is memory)
                String op0 = inst.getDefaultOperandRepresentation(0);
                if (op0.contains("[") && op0.contains("0xd0")) {
                    Function f = getFunctionContaining(inst.getAddress());
                    if (f != null && seen.add(f.getName())) {
                        count++;
                        println("\n*** WRITE to +0xD0 at " + inst.getAddress() + " in " + f.getName() + " ***");
                        println("  Instruction: " + instStr);
                        
                        // Decompile
                        ghidra.app.decompiler.DecompInterface d = new ghidra.app.decompiler.DecompInterface();
                        d.openProgram(currentProgram);
                        ghidra.app.decompiler.DecompileResults r = d.decompileFunction(f, 120, monitor);
                        if (r.decompileCompleted()) {
                            String[] lines = r.getDecompiledFunction().getC().split("\n");
                            for (int i = 0; i < Math.min(lines.length, 150); i++) println(lines[i]);
                            if (lines.length > 150) println("... (" + (lines.length - 150) + " more)");
                        }
                        d.dispose();
                        
                        Reference[] refs = getReferencesTo(f.getEntryPoint());
                        if (refs.length > 0 && refs.length < 20) {
                            println("\nCallers (" + refs.length + "):");
                            for (Reference ref : refs) {
                                Function c = getFunctionContaining(ref.getFromAddress());
                                if (c != null) println("  " + c.getName() + " at " + c.getEntryPoint());
                            }
                        }
                    }
                }
            }
        }
        println("\n=== DONE (found " + count + ") ===");
    }
}
