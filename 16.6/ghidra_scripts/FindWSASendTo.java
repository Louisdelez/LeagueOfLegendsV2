// FindWSASendTo.java - Find all callers of WSASendTo in the binary
// Run in Ghidra's Script Manager on stub.dll or LoLPrivate.exe
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.util.*;

public class FindWSASendTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("=== Finding WSASendTo callers ===");

        // Search for WSASendTo import
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getAllSymbols(true);

        List<String> targets = Arrays.asList(
            "WSASendTo", "sendto", "WSARecvFrom", "recvfrom",
            "send", "recv", "WSASend", "WSARecv",
            "Blowfish", "blowfish", "encrypt", "decrypt",
            "Encrypt", "Decrypt", "bf_", "BF_"
        );

        println("Searching for network and crypto symbols...");

        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            String name = sym.getName();

            for (String target : targets) {
                if (name.contains(target)) {
                    println("FOUND: " + name + " at " + sym.getAddress());

                    // Find references (callers)
                    Reference[] refs = getReferencesTo(sym.getAddress());
                    if (refs.length > 0) {
                        println("  Callers (" + refs.length + "):");
                        for (int i = 0; i < Math.min(refs.length, 20); i++) {
                            Address caller = refs[i].getFromAddress();
                            Function func = getFunctionContaining(caller);
                            String funcName = func != null ? func.getName() : "???";
                            println("    " + caller + " in " + funcName);
                        }
                    }
                    break;
                }
            }
        }

        // Also search for string references
        println("\n=== Searching for crypto-related strings ===");
        String[] searchStrings = {
            "Blowfish", "encrypt", "decrypt", "cipher",
            "WSASendTo", "sendto", "MultiplayerClient",
            "ENet", "enet", "checksum"
        };

        // Search in defined strings
        DataIterator dataIter = currentProgram.getListing().getDefinedData(true);
        while (dataIter.hasNext()) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String val = data.getDefaultValueRepresentation();
                for (String s : searchStrings) {
                    if (val.toLowerCase().contains(s.toLowerCase())) {
                        println("STRING: " + val + " at " + data.getAddress());
                        break;
                    }
                }
            }
        }

        println("\n=== Done ===");
    }
}
