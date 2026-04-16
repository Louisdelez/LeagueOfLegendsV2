using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

class PacketCapture
{
    static void Main(string[] args)
    {
        string outDir = @"D:\LeagueOfLegendsV2\riot_captures";
        Directory.CreateDirectory(outDir);
        
        // Get local IP
        string localIP = "0.0.0.0";
        foreach (var addr in Dns.GetHostAddresses(Dns.GetHostName()))
        {
            if (addr.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(addr))
            {
                localIP = addr.ToString();
                break;
            }
        }
        
        Console.WriteLine($"Capturing on {localIP}...");
        Console.WriteLine($"Output: {outDir}");
        
        // Raw socket to capture all IP packets
        Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);
        sock.Bind(new IPEndPoint(IPAddress.Parse(localIP), 0));
        sock.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        
        // SIO_RCVALL - receive all packets
        byte[] optIn = BitConverter.GetBytes(1);
        sock.IOControl(unchecked((int)0x98000001), optIn, null);
        
        byte[] buffer = new byte[65535];
        int count = 0;
        int udpCount = 0;
        
        Console.WriteLine("Listening... Press Ctrl+C to stop.");
        
        while (true)
        {
            int len = sock.Receive(buffer);
            count++;
            
            // Parse IP header
            int protocol = buffer[9];
            if (protocol != 17) continue; // UDP only
            
            int ipHeaderLen = (buffer[0] & 0x0F) * 4;
            int srcPort = (buffer[ipHeaderLen] << 8) | buffer[ipHeaderLen + 1];
            int dstPort = (buffer[ipHeaderLen + 2] << 8) | buffer[ipHeaderLen + 3];
            
            // Filter: only game traffic (port 50768 = our local game port)
            if (srcPort != 50768 && dstPort != 50768) continue;
            
            udpCount++;
            string srcIP = $"{buffer[12]}.{buffer[13]}.{buffer[14]}.{buffer[15]}";
            string dstIP = $"{buffer[16]}.{buffer[17]}.{buffer[18]}.{buffer[19]}";
            
            string direction = srcPort == 50768 ? "SEND" : "RECV";
            int udpLen = len - ipHeaderLen;
            
            string filename = Path.Combine(outDir, $"{direction}_{udpCount:D5}_{udpLen}B.bin");
            File.WriteAllBytes(filename, buffer.AsSpan(ipHeaderLen, udpLen).ToArray());
            
            Console.WriteLine($"[{udpCount}] {direction} {srcIP}:{srcPort} -> {dstIP}:{dstPort} ({udpLen}B)");
        }
    }
}
