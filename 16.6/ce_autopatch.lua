-- Auto-attach to LoLPrivate.exe and patch CRC check
-- Run via: "cheatengine-x86_64.exe" -LUASCRIPT ce_autopatch.lua

-- Open the process
local pid = nil
local pl = getProcesslist()
for i = 0, strings_getCount(pl) - 1 do
    local s = strings_getString(pl, i)
    if s:find("LoLPrivate") then
        pid = tonumber(s:match("^(%x+)"), 16)
        break
    end
end
strings_destroy(pl)

if pid then
    print(string.format("Found LoLPrivate.exe PID: %d", pid))
    openProcess(pid)
else
    print("Trying by name...")
    openProcess("LoLPrivate.exe")
end

sleep(500)

-- Get base address
local base = getAddress("LoLPrivate.exe")
if base == nil or base == 0 then
    print("ERROR: Cannot find LoLPrivate.exe base address")
    closeCE()
    return
end
print(string.format("Base: 0x%X", base))

-- Target: base + 0x572827
local target = base + 0x572827
print(string.format("Target: 0x%X", target))

-- Read current bytes
local bytes = readBytes(target, 6, true)
if bytes == nil then
    print("ERROR: Cannot read target address")
    closeCE()
    return
end

print(string.format("Current bytes: %02X %02X %02X %02X %02X %02X",
    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]))

-- Check if already patched
if bytes[1] == 0x90 and bytes[4] == 0xB0 then
    print("Already patched!")
    closeCE()
    return
end

-- Check if bytes match expected
if bytes[1] == 0x44 and bytes[2] == 0x3B and bytes[3] == 0xE0 and
   bytes[4] == 0x0F and bytes[5] == 0x94 and bytes[6] == 0xC0 then
    print("Bytes match! Applying patch...")

    -- Method 1: writeBytes (uses CE's internal method, kernel if available)
    writeBytes(target, 0x90, 0x90, 0x90, 0xB0, 0x01, 0x90)

    sleep(100)

    -- Verify
    local after = readBytes(target, 6, true)
    print(string.format("After writeBytes: %02X %02X %02X %02X %02X %02X",
        after[1], after[2], after[3], after[4], after[5], after[6]))

    if after[1] == 0x90 and after[4] == 0xB0 then
        print("=== PATCH SUCCESSFUL! ===")
        -- Write result file
        local f = io.open("D:/LeagueOfLegendsV2/patch_result.txt", "w")
        f:write("PATCH_OK\n")
        f:close()
    else
        print("writeBytes failed, trying dbk kernel write...")

        -- Method 2: Explicit kernel mode write
        local processHandle = getOpenedProcessID()
        dbk_writesProcessMemory(processHandle, target,
            string.char(0x90, 0x90, 0x90, 0xB0, 0x01, 0x90), 6)

        sleep(100)

        after = readBytes(target, 6, true)
        print(string.format("After dbk: %02X %02X %02X %02X %02X %02X",
            after[1], after[2], after[3], after[4], after[5], after[6]))

        if after[1] == 0x90 and after[4] == 0xB0 then
            print("=== PATCH SUCCESSFUL via kernel! ===")
            local f = io.open("D:/LeagueOfLegendsV2/patch_result.txt", "w")
            f:write("PATCH_OK_KERNEL\n")
            f:close()
        else
            print("=== PATCH FAILED - stub.dll blocking ===")
            local f = io.open("D:/LeagueOfLegendsV2/patch_result.txt", "w")
            f:write("PATCH_FAILED\n")
            f:close()
        end
    end
else
    print(string.format("WARNING: Unexpected bytes at target! Expected 44 3B E0 0F 94 C0"))
    local f = io.open("D:/LeagueOfLegendsV2/patch_result.txt", "w")
    f:write("WRONG_BYTES\n")
    f:close()
end

-- Close CE after a delay
sleep(1000)
closeCE()
