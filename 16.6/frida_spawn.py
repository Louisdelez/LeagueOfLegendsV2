import frida
import sys
import time

exe = r'D:\LeagueOfLegendsV2\client-private\Game\LoLPrivate.exe'
args = ['127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1', '-Product=LoL', '-PlayerID=1', '-GameID=1', r'-GameBaseDir=D:\LeagueOfLegendsV2\client-private', '-Region=EUW', '-Locale=fr_FR', '-SkipBuild', '-EnableCrashpad=false', '-LNPBlob=N6oAFO++rd4=']

print('Spawning with Frida...')
try:
    device = frida.get_local_device()
    pid = device.spawn([exe] + args)
    print(f'Spawned PID {pid}')
    session = device.attach(pid)
    print('Attached!')
    
    script = session.create_script("""
    var base = Module.findBaseAddress('LoLPrivate.exe');
    if (base) {
        send('Base: ' + base);
        var crcAddr = base.add(0x577F10);
        send('CRC func at: ' + crcAddr);
        var bytes = crcAddr.readByteArray(6);
        var hex = Array.from(new Uint8Array(bytes)).map(function(b) { return ('0'+b.toString(16)).slice(-2); }).join(' ');
        send('CRC bytes: ' + hex);
    } else {
        send('Module not found');
    }
    """)
    
    def on_msg(msg, data):
        if msg['type'] == 'send':
            print('[FRIDA] ' + str(msg['payload']))
        else:
            print('[FRIDA] ' + str(msg))
    
    script.on('message', on_msg)
    script.load()
    
    print('Resuming process...')
    device.resume(pid)
    time.sleep(5)
    print('Done.')
except Exception as e:
    print(f'Error: {e}')
