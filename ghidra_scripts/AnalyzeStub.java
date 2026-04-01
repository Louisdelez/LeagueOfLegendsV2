import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class AnalyzeStub extends GhidraScript {
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        PrintWriter out = new PrintWriter(new FileWriter("D:/LeagueOfLegendsV2/stub_analysis.txt"));
        
        // Find sendto and all network imports
        String[] targets = {"sendto", "WSASendTo", "send", "WSASend", "recvfrom", "connect", "socket", "bind"};
        for (String name : targets) {
            SymbolIterator syms = st.getSymbols(name);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                out.println("=== " + name + " at " + s.getAddress() + " ===");
                Reference[] refs = getReferencesTo(s.getAddress());
                out.println(refs.length + " callers");
                for (int i = 0; i < Math.min(2, refs.length); i++) {
                    Function caller = fm.getFunctionContaining(refs[i].getFromAddress());
                    if (caller != null) {
                        out.println("Caller: " + caller.getName() + " @ " + caller.getEntryPoint());
                        DecompileResults r = decomp.decompileFunction(caller, 30, monitor);
                        if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                    }
                }
            }
        }
        
        // Search for Blowfish/encrypt strings
        out.println("\n=== BLOWFISH/ENCRYPT STRINGS ===");
        ghidra.program.model.mem.Memory mem = currentProgram.getMemory();
        String[] searches = {"Blowfish", "blowfish", "BF_encrypt", "BF_set_key", "enet_", "ENet"};
        for (String s : searches) {
            Address addr = mem.findBytes(currentProgram.getMinAddress(), s.getBytes("ASCII"), null, true, monitor);
            if (addr != null) {
                out.println("Found '" + s + "' at " + addr);
                Reference[] refs = getReferencesTo(addr);
                for (Reference ref : refs) {
                    Function f = fm.getFunctionContaining(ref.getFromAddress());
                    if (f != null) out.println("  Ref from: " + f.getName());
                }
            }
        }
        
        out.close();
        println("Saved to D:/LeagueOfLegendsV2/stub_analysis.txt");
        decomp.closeProgram();
    }
}
