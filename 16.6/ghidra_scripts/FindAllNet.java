import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import java.io.*;

public class FindAllNet extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        
        PrintWriter out = new PrintWriter(new FileWriter("D:/LeagueOfLegendsV2/ghidra_net.txt"));
        
        // Search for ALL Winsock/network symbols
        String[] netSyms = {"sendto", "WSASendTo", "send", "WSASend", 
                           "recvfrom", "WSARecvFrom", "recv", "WSARecv",
                           "connect", "WSAConnect", "bind", "socket", "WSASocket",
                           "WSAStartup", "closesocket", "setsockopt"};
        
        for (String name : netSyms) {
            SymbolIterator syms = st.getSymbols(name);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                out.println("=== " + name + " at " + s.getAddress() + " ===");
                Reference[] refs = getReferencesTo(s.getAddress());
                out.println("  " + refs.length + " callers");
                for (int i = 0; i < Math.min(3, refs.length); i++) {
                    Function caller = fm.getFunctionContaining(refs[i].getFromAddress());
                    if (caller != null) {
                        out.println("  Caller: " + caller.getName() + " @ " + caller.getEntryPoint());
                        // Decompile first caller of sendto/WSASendTo
                        if ((name.equals("sendto") || name.equals("WSASendTo")) && i == 0) {
                            DecompileResults r = decomp.decompileFunction(caller, 30, monitor);
                            if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                        }
                    }
                }
            }
        }
        
        out.close();
        println("Saved to D:/LeagueOfLegendsV2/ghidra_net.txt");
        decomp.closeProgram();
    }
}
