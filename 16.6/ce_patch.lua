-- Cheat Engine Lua script to patch CRC check via kernel mode
-- Open the Lua Engine window (CE main: Table → Show Lua Script)
-- Paste this and click Execute

-- Get the base address
local base = getAddress("LoLPrivate.exe")
print(string.format("Base: %X", base))

-- Target: base + 0x572827
local target = base + 0x572827

-- Read current bytes
local bytes = readBytes(target, 6, true)
print(string.format("Current: %02X %02X %02X %02X %02X %02X", 
    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]))

-- Check if it's the right bytes (44 3B E0 0F 94 C0)
if bytes[1] == 0x44 and bytes[2] == 0x3B and bytes[3] == 0xE0 then
    print("Bytes match! Patching...")
    
    -- Try kernel-mode write
    local ok = writeBytes(target, 0x90, 0x90, 0x90, 0xB0, 0x01, 0x90)
    
    -- Verify
    local after = readBytes(target, 6, true)
    print(string.format("After:   %02X %02X %02X %02X %02X %02X",
        after[1], after[2], after[3], after[4], after[5], after[6]))
    
    if after[1] == 0x90 then
        print("*** PATCH SUCCESSFUL! ***")
    else
        print("Patch FAILED - trying dbk_writesProcessMemory...")
        -- Try with explicit kernel function
        dbk_writesProcessMemory(getOpenedProcessID(), target, 
            string.char(0x90, 0x90, 0x90, 0xB0, 0x01, 0x90), 6)
        
        after = readBytes(target, 6, true)
        print(string.format("After dbk: %02X %02X %02X %02X %02X %02X",
            after[1], after[2], after[3], after[4], after[5], after[6]))
        if after[1] == 0x90 then
            print("*** PATCH SUCCESSFUL via dbk! ***")
        else
            print("Still failed. stub.dll is blocking all writes.")
        end
    end
else
    print("Bytes DON'T match - already patched or wrong address")
end
