// AnalyzeStubDll.java - Find network functions in stub.dll
// stub.dll loads WSASendTo dynamically via GetProcAddress
// We search for GetProcAddress calls and trace the loaded function pointers
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import java.util.*;

public class AnalyzeStubDll extends GhidraScript {

    @Override
    public void run() throws Exception {
        Address imageBase = currentProgram.getImageBase();
        println("Image base: " + imageBase);
        println("Program: " + currentProgram.getName());

        // Search for "WSASendTo" string
        println("\n=== Searching for network function name strings ===");
        String[] funcNames = {"WSASendTo", "WSARecvFrom", "sendto", "recvfrom",
                              "WSASend", "WSARecv", "send", "recv",
                              "GetProcAddress", "LoadLibrary", "ws2_32"};

        for (String name : funcNames) {
            byte[] pattern = name.getBytes();
            Address found = currentProgram.getMemory().findBytes(
                currentProgram.getMinAddress(), currentProgram.getMaxAddress(),
                pattern, null, true, monitor);
            int count = 0;
            while (found != null && count < 3) {
                // Verify null-terminated
                try {
                    byte next = currentProgram.getMemory().getByte(found.add(name.length()));
                    if (next == 0 || next == '"' || next == 0x20) {
                        println("'" + name + "' at " + found);
                        // Find xrefs
                        Reference[] refs = getReferencesTo(found);
                        for (Reference ref : refs) {
                            Function f = getFunctionContaining(ref.getFromAddress());
                            println("  xref from " + ref.getFromAddress() +
                                    " in " + (f != null ? f.getName() : "<none>"));
                            if (f != null && count == 0) {
                                decompileAndPrint(f, 80);
                            }
                        }
                        count++;
                    }
                } catch (Exception e) {}
                found = currentProgram.getMemory().findBytes(
                    found.add(1), currentProgram.getMaxAddress(),
                    pattern, null, true, monitor);
            }
        }

        // Search for GetProcAddress import
        println("\n=== GetProcAddress import ===");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator symbols = st.getAllSymbols(true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            if (sym.getName().contains("GetProcAddress") ||
                sym.getName().contains("LoadLibrary")) {
                println("Symbol: " + sym.getName() + " at " + sym.getAddress());
                Reference[] refs = getReferencesTo(sym.getAddress());
                println("  References: " + refs.length);
                Set<String> callers = new HashSet<>();
                for (Reference ref : refs) {
                    Function f = getFunctionContaining(ref.getFromAddress());
                    if (f != null && !callers.contains(f.getName())) {
                        callers.add(f.getName());
                        println("  Called by " + f.getName() + " at " + f.getEntryPoint());
                    }
                }
            }
        }

        // Search for socket/network related constants
        println("\n=== Searching for network constants ===");
        // AF_INET = 2, SOCK_DGRAM = 2, IPPROTO_UDP = 17
        // Port 5119 = 0x13FF (big-endian for network byte order: FF13)

        println("\n=== DONE ===");
    }

    private void decompileAndPrint(Function func, int maxLines) {
        try {
            ghidra.app.decompiler.DecompInterface decomp = new ghidra.app.decompiler.DecompInterface();
            decomp.openProgram(currentProgram);
            ghidra.app.decompiler.DecompileResults results = decomp.decompileFunction(func, 60, monitor);
            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                String[] lines = code.split("\n");
                println("--- " + func.getName() + " (" + lines.length + " lines) ---");
                for (int i = 0; i < Math.min(lines.length, maxLines); i++) {
                    println(lines[i]);
                }
                if (lines.length > maxLines) println("... (" + (lines.length - maxLines) + " more lines)");
            }
            decomp.dispose();
        } catch (Exception e) {
            println("Decompile failed: " + e.getMessage());
        }
    }
}
