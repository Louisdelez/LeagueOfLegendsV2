// Find functions related to network/encryption in LoL client
// @category Analysis
// @keybinding
// @menupath
// @toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindNetworkFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Searching for network/encryption functions ===");
        
        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();
        
        // Search for imported functions
        String[] targets = {"sendto", "WSASendTo", "recvfrom", "WSARecvFrom", 
                           "connect", "bind", "socket", "send", "recv"};
        
        for (String name : targets) {
            SymbolIterator syms = st.getSymbols(name);
            while (syms.hasNext()) {
                Symbol s = syms.next();
                println("FOUND: " + name + " at " + s.getAddress() + " type=" + s.getSymbolType());
                
                // Find references (callers)
                Reference[] refs = getReferencesTo(s.getAddress());
                int count = 0;
                for (Reference ref : refs) {
                    if (count++ > 5) break;
                    Function caller = fm.getFunctionContaining(ref.getFromAddress());
                    String callerName = caller != null ? caller.getName() : "unknown";
                    println("  Called from: " + ref.getFromAddress() + " in " + callerName);
                }
            }
        }
        
        // Search for strings
        println("\n=== Searching for key strings ===");
        Memory mem = currentProgram.getMemory();
        
        String[] searchStrings = {"Hard Connect", "MultiplayerSettings", "Encryption=", 
                                  "encryptionKey", "MultiplayerClient"};
        
        for (String searchStr : searchStrings) {
            byte[] searchBytes = searchStr.getBytes("ASCII");
            Address addr = mem.findBytes(currentProgram.getMinAddress(), searchBytes, null, true, monitor);
            if (addr != null) {
                println("STRING: '" + searchStr + "' at " + addr);
                
                // Find data references to this address
                Reference[] refs = getReferencesTo(addr);
                for (Reference ref : refs) {
                    Function func = fm.getFunctionContaining(ref.getFromAddress());
                    String funcName = func != null ? func.getName() : "unknown";
                    println("  Referenced from: " + ref.getFromAddress() + " in " + funcName);
                }
            }
        }
        
        println("\n=== Done ===");
    }
}
