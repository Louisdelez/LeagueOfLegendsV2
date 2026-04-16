import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class FindCertRefs extends GhidraScript {
    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // The Riot CA cert is at file offset 0x19EEBD0
        // Since .rdata has VA == RawOffset, RVA = 0x19EEBD0
        // Ghidra address = imageBase + 0x19EEBD0 = 0x1419EEBD0
        long certRVA = 0x19EEBD0L;
        Address certAddr = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(0x140000000L + certRVA));
        println("=== Searching xrefs to Riot CA cert at " + certAddr + " ===");

        // Find references
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(certAddr)) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  Ref from " + from + 
                    (fn != null ? " in " + fn.getName() + " at " + fn.getEntryPoint() : ""));
        }

        // Also search for the rclient cert at 0x19EE230
        long rclientRVA = 0x19EE230L;
        Address rclientAddr = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(0x140000000L + rclientRVA));
        println("\n=== Xrefs to rclient cert at " + rclientAddr + " ===");
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(rclientAddr)) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  Ref from " + from + 
                    (fn != null ? " in " + fn.getName() + " at " + fn.getEntryPoint() : ""));
        }

        // Search for the FIRST cert (DigiCert at 0x19EDE10)
        long digiRVA = 0x19EDE10L;
        Address digiAddr = currentProgram.getAddressFactory().getAddress(
            Long.toHexString(0x140000000L + digiRVA));
        println("\n=== Xrefs to first cert (DigiCert) at " + digiAddr + " ===");
        for (Reference ref : currentProgram.getReferenceManager().getReferencesTo(digiAddr)) {
            Address from = ref.getFromAddress();
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            println("  Ref from " + from + 
                    (fn != null ? " in " + fn.getName() + " at " + fn.getEntryPoint() +
                            " size=" + fn.getBody().getNumAddresses() : ""));
            // Decompile the function that references the certs
            if (fn != null) {
                DecompileResults r = decomp.decompileFunction(fn, 180, monitor);
                if (r.decompileCompleted()) {
                    String[] lines = r.getDecompiledFunction().getC().split("\n");
                    println("  Lines: " + lines.length);
                    for (int i = 0; i < Math.min(30, lines.length); i++)
                        println("    " + lines[i]);
                }
            }
        }

        // Also search for a cert size table (array of sizes like 969, 1241, 1060...)
        // These would be near the cert pointers
        println("\n=== Searching for cert pointer/size arrays ===");
        // Search for the value 0x19EEBD0 (cert offset as pointer) stored in data
        // In the relocated binary, this would be imageBase + 0x19EEBD0
        // But in the file, it could be just the RVA 0x19EEBD0 stored as a 32-bit value
        // Search for bytes BD EB 9E 01 (LE encoding of 0x019EEBD0) in the binary
        byte[] pattern = {(byte)0xD0, (byte)0xEB, (byte)0x9E, (byte)0x01};
        Address searchStart = currentProgram.getMinAddress();
        Address searchEnd = currentProgram.getMaxAddress();
        int found = 0;
        Address current = currentProgram.getMemory().findBytes(searchStart, searchEnd, pattern, null, true, monitor);
        while (current != null && found < 10) {
            found++;
            println("  Pattern at " + current);
            current = currentProgram.getMemory().findBytes(current.add(1), searchEnd, pattern, null, true, monitor);
        }

        println("\n=== DONE ===");
        decomp.dispose();
    }
}
