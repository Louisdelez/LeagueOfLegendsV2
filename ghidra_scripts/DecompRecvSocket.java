import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;

public class DecompRecvSocket extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // recvfrom return address at RVA 0x58B099 → Ghidra address 0x14058B099
        Address target = currentProgram.getAddressFactory().getAddress("14058b099");
        println("Target: " + target);

        // Find function containing this address
        Function func = currentProgram.getFunctionManager().getFunctionContaining(target);
        if (func != null) {
            println("=== FUNCTION at " + func.getEntryPoint() + " ===");
            println("Name: " + func.getName());
            println("Size: " + func.getBody().getNumAddresses());
            DecompileResults result = decomp.decompileFunction(func, 180, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                for (String line : code.split("\n")) println(line);
            } else {
                println("Decompile failed: " + result.getErrorMessage());
            }
        } else {
            println("No function at target! Creating one...");
            // Try to find the function start by scanning backwards for common prologue
            // List nearby functions
            println("\nFunctions in range 0x58AF00-0x58B200:");
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(
                currentProgram.getAddressFactory().getAddress("14058af00"), true);
            while (iter.hasNext()) {
                Function f = iter.next();
                if (f.getEntryPoint().getOffset() > 0x14058b200L) break;
                println("  " + f.getEntryPoint() + " " + f.getName() +
                        " size=" + f.getBody().getNumAddresses());
            }

            // Disassemble instructions around the target
            println("\nInstructions around 14058b080-14058b0b0:");
            for (long addr = 0x14058b070L; addr < 0x14058b0c0L; ) {
                Address a = currentProgram.getAddressFactory().getAddress(String.format("%x", addr));
                Instruction inst = currentProgram.getListing().getInstructionAt(a);
                if (inst != null) {
                    println("  " + a + ": " + inst);
                    addr += inst.getLength();
                } else {
                    addr++;
                }
            }

            // Try creating a function at a likely start
            // Common start: the instruction after the previous function's RET
            // Try 14058af30, 14058b000, etc.
            long[] candidates = {0x14058af30L, 0x14058af40L, 0x14058b000L, 0x14058b010L, 0x14058b020L};
            for (long cand : candidates) {
                Address ca = currentProgram.getAddressFactory().getAddress(String.format("%x", cand));
                Instruction ci = currentProgram.getListing().getInstructionAt(ca);
                if (ci != null) {
                    println("\nCandidate " + ca + ": " + ci);
                    try {
                        Function nf = currentProgram.getFunctionManager().createFunction(
                            "RECV_SOCKET_" + ca, ca,
                            new ghidra.program.model.address.AddressSet(ca,
                                currentProgram.getAddressFactory().getAddress(String.format("%x", cand + 0x200))),
                            ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        func = currentProgram.getFunctionManager().getFunctionContaining(target);
                        if (func != null) {
                            println("Created function, decompiling...");
                            DecompileResults result = decomp.decompileFunction(func, 180, monitor);
                            if (result.decompileCompleted()) {
                                String code = result.getDecompiledFunction().getC();
                                for (String line : code.split("\n")) println(line);
                            }
                            break;
                        }
                    } catch (Exception e) {
                        println("  Failed: " + e.getMessage());
                    }
                }
            }
        }

        // Also decompile FUN_140588f70 caller chain
        println("\n=== Xrefs to FUN_140588f70 ===");
        Address f588 = currentProgram.getAddressFactory().getAddress("140588f70");
        for (ghidra.program.model.symbol.Reference ref :
             currentProgram.getReferenceManager().getReferencesTo(f588)) {
            println("  Called from: " + ref.getFromAddress());
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                println("  In function: " + caller.getName() + " at " + caller.getEntryPoint());
            }
        }

        decomp.dispose();
    }
}
