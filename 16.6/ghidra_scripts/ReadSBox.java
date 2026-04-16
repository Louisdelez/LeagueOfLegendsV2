import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
public class ReadSBox extends GhidraScript {
    public void run() throws Exception {
        // Read the crypto context that was captured by nethook
        // S-box starts at offset 0x58 (88) from the context base
        // We'll read from the binary's copy of the BF tables

        // Actually, we need the RUNTIME S-box. Let me instead compute
        // BF_encrypt of a known non-zero value and compare.
        // We can't do that from Ghidra (static analysis).

        // Instead, let me check if our C# S-box matches by reading
        // the captured CRYPTO_CTX binary file's S-box.
        println("Use QuickDecrypt.cs to verify S-box match");
        println("Captured context at: D:\LeagueOfLegendsV2\client-private\Game\nethook_logs\CRYPTO_CTX_*.bin");
    }
}
