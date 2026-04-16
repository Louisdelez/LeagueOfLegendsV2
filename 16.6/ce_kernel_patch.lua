-- Cheat Engine Lua script - CRC Bypass via kernel driver
-- Instructions:
-- 1. Open Cheat Engine as Admin
-- 2. Attach to "League of Legends.exe" (File → Open Process)
-- 3. IMPORTANT: In Settings → Extra, check "Use kernel mode readprocessmemory"
--    and "Use kernel mode writeprocessmemory"
-- 4. Table → Show Cheat Table Lua Script (Ctrl+Alt+L)
-- 5. Paste this script and click Execute

-- Enable kernel-mode access
dbk_initialize()

-- Get base address of the game
local base = getAddress("League of Legends.exe")
if base == nil or base == 0 then
  print("ERROR: Can't find League of Legends.exe")
  print("Make sure you've attached to the process first!")
  return
end
print(string.format("Base: 0x%X", base))

-- Target: CMP R12D,EAX (44 3B E0) followed by SETE AL (0F 94 C0)
local target = base + 0x572827

-- Read current bytes using kernel mode
local bytes = readBytes(target, 6, true)
if bytes == nil then
  print("ERROR: Can't read target address")
  return
end
print(string.format("Current: %02X %02X %02X %02X %02X %02X",
    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6]))

if bytes[1] == 0x90 and bytes[4] == 0xB0 then
  print("Already patched!")
  return
end

if bytes[1] ~= 0x44 or bytes[2] ~= 0x3B or bytes[3] ~= 0xE0 then
  print("ERROR: Wrong bytes at target! Not the expected CRC check.")
  return
end

print("Bytes verified! Patching via auto-assemble...")

-- Use auto-assemble which goes through the kernel driver
local script = string.format([[
[enable]
%X:
nop
nop
nop
mov al,1
nop
]], target)

local ok, err = autoAssemble(script)
if ok then
  print("=== autoAssemble SUCCESS! ===")
else
  print("autoAssemble failed: " .. tostring(err))
  print("Trying direct kernel write...")

  -- Try direct kernel-mode write
  writeBytes(target, 0x90, 0x90, 0x90, 0xB0, 0x01, 0x90)
end

-- Verify
local after = readBytes(target, 6, true)
print(string.format("After:   %02X %02X %02X %02X %02X %02X",
    after[1], after[2], after[3], after[4], after[5], after[6]))

if after[1] == 0x90 and after[4] == 0xB0 then
  print("")
  print("╔════════════════════════════════════╗")
  print("║   CRC CHECK PATCHED SUCCESSFULLY!  ║")
  print("╚════════════════════════════════════╝")
  print("")
  print("The server can now send non-echo packets!")
else
  print("")
  print("PATCH FAILED - stub.dll blocking even kernel writes")
  print("Try: Settings → Extra → Enable 'Use kernel mode writeprocessmemory'")
end
