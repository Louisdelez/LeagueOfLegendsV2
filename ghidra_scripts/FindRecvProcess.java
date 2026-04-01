import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class FindRecvProcess extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Find the recvfrom callers in LoLPrivate.exe
        // The receive processing chain: recvfrom -> process_packet -> decrypt -> parse

        // Search for the NET_58e860 send function area - the receive should be nearby
        // sendto caller: +0x58ECBB
        // The recv processing is likely in the same networking module

        // Let's look at functions around 0x58E000-0x590000 that call recvfrom
        println("=== SEARCHING FOR RECEIVE PROCESSING FUNCTIONS ===");

        // Find recvfrom import
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
        Function recvfromFunc = null;
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            if (f.getName().contains("recvfrom")) {
                println("Found recvfrom: " + f.getName() + " at " + f.getEntryPoint());
                recvfromFunc = f;
            }
            if (f.getName().contains("WSARecvFrom")) {
                println("Found WSARecvFrom: " + f.getName() + " at " + f.getEntryPoint());
            }
        }

        // Find callers of recvfrom
        if (recvfromFunc != null) {
            println("\n=== CALLERS OF recvfrom ===");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(recvfromFunc.getEntryPoint());
            int count = 0;
            while (refs.hasNext() && count < 20) {
                Reference ref = refs.next();
                Address caller = ref.getFromAddress();
                Function callerFunc = currentProgram.getFunctionManager().getFunctionContaining(caller);
                if (callerFunc != null) {
                    println("  Caller: " + callerFunc.getName() + " at " + callerFunc.getEntryPoint() + " (ref from " + caller + ")");

                    // Decompile the caller
                    if (count < 3) {
                        DecompileResults result = decomp.decompileFunction(callerFunc, 120, monitor);
                        if (result.decompileCompleted()) {
                            String code = result.getDecompiledFunction().getC();
                            String[] lines = code.split("\n");
                            println("  Decompiled (" + lines.length + " lines):");
                            for (String line : lines) {
                                if (line.contains("recv") || line.contains("FUN_") ||
                                    line.contains("param_") || line.contains("return") ||
                                    line.contains("if ") || line.contains("while") ||
                                    line.contains("socket") || line.contains("SOCKET")) {
                                    println("    " + line.trim());
                                }
                            }
                        }
                    }
                    count++;
                }
            }
        }

        // Also look for the function that processes received ENet data
        // This is usually called from the main game loop after recvfrom
        // Look for functions near the send loop (0x58E860)
        println("\n=== FUNCTIONS NEAR SEND LOOP (0x58E000-0x590000) ===");
        Address start = currentProgram.getAddressFactory().getAddress("14058e000");
        Address end = currentProgram.getAddressFactory().getAddress("140590000");
        funcIter = currentProgram.getFunctionManager().getFunctions(start, true);
        while (funcIter.hasNext()) {
            Function f = funcIter.next();
            if (f.getEntryPoint().compareTo(end) > 0) break;
            String name = f.getName();
            println("  " + f.getEntryPoint() + " " + name + " (" + f.getBody().getNumAddresses() + " bytes)");
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
