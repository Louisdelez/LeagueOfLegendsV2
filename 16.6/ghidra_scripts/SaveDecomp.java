import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class SaveDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        
        String outPath = "D:/LeagueOfLegendsV2/ghidra_output.txt";
        PrintWriter out = new PrintWriter(new FileWriter(outPath));
        
        // Find function containing Hard Connect reference at 0x14067b36c
        Address ref = toAddr(0x14067b36cL);
        for (long off = 0x14067b36cL; off > 0x14067b000L; off--) {
            Function f = fm.getFunctionContaining(toAddr(off));
            if (f != null) {
                out.println("=== HARD CONNECT FUNC: " + f.getName() + " @ " + f.getEntryPoint() + " ===");
                DecompileResults r = decomp.decompileFunction(f, 60, monitor);
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                break;
            }
        }
        
        // Decompile FUN_140728560 (encryptionKey user)
        Function f1 = fm.getFunctionAt(toAddr(0x140728560L));
        if (f1 != null) {
            out.println("\n=== ENCRYPTION KEY FUNC: " + f1.getName() + " @ " + f1.getEntryPoint() + " ===");
            DecompileResults r = decomp.decompileFunction(f1, 60, monitor);
            if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
        }
        
        // Find sendto callers  
        out.println("\n=== SENDTO CALLERS ===");
        SymbolIterator syms = st.getSymbols("sendto");
        while (syms.hasNext()) {
            Symbol s = syms.next();
            out.println("sendto at " + s.getAddress());
            Reference[] refs = getReferencesTo(s.getAddress());
            for (int i = 0; i < Math.min(3, refs.length); i++) {
                Function caller = fm.getFunctionContaining(refs[i].getFromAddress());
                if (caller != null) {
                    out.println("--- Caller: " + caller.getName() + " ---");
                    DecompileResults r = decomp.decompileFunction(caller, 30, monitor);
                    if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                }
            }
        }
        
        out.close();
        println("Output saved to " + outPath);
        decomp.closeProgram();
    }
}
