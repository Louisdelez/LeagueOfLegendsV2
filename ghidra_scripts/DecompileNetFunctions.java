import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.flatapi.*;

public class DecompileNetFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        FunctionManager fm = currentProgram.getFunctionManager();
        
        // Key addresses found in first pass
        long[] addresses = {
            0x14067b36cL,  // References "Hard Connect"
            0x140728560L,  // FUN_140728560 - uses encryptionKey
            0x140882e40L,  // FUN_140882e40 - uses encryptionKey
        };
        
        for (long addr : addresses) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
            Function func = fm.getFunctionContaining(a);
            
            if (func == null) {
                println("No function at " + Long.toHexString(addr));
                continue;
            }
            
            println("\n=== FUNCTION: " + func.getName() + " at " + func.getEntryPoint() + " ===");
            println("Size: " + func.getBody().getNumAddresses() + " bytes");
            
            // Get called functions
            Reference[] refs = getReferencesFrom(func.getEntryPoint());
            
            // Decompile
            DecompileResults result = decomp.decompileFunction(func, 30, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                // Print first 100 lines
                String[] lines = code.split("\n");
                int maxLines = Math.min(80, lines.length);
                for (int i = 0; i < maxLines; i++) {
                    println(lines[i]);
                }
                if (lines.length > maxLines) {
                    println("... (" + (lines.length - maxLines) + " more lines)");
                }
            } else {
                println("Decompilation failed: " + result.getErrorMessage());
            }
        }
        
        // Also find and decompile sendto callers
        println("\n=== Looking for sendto imports ===");
        SymbolTable st = currentProgram.getSymbolTable();
        String[] netFuncs = {"sendto", "WSASendTo", "send"};
        for (String name : netFuncs) {
            SymbolIterator syms = st.getSymbols(name);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                println("Import: " + name + " at " + s.getAddress());
                Reference[] refs = getReferencesTo(s.getAddress());
                for (int i = 0; i < Math.min(3, refs.length); i++) {
                    Function caller = fm.getFunctionContaining(refs[i].getFromAddress());
                    if (caller != null) {
                        println("  Caller: " + caller.getName() + " at " + caller.getEntryPoint());
                    }
                }
            }
        }
        
        decomp.closeProgram();
    }
}
