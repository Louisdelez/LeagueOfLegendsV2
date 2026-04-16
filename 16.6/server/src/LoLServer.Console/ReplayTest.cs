using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace LoLServer.Console;

/// <summary>
/// Replays captured packets against the server and checks for responses.
/// Run with: dotnet run -- --replay-test [--port=5119]
/// </summary>
public static class ReplayTest
{
    public static void Run(int port = 5119)
    {
        var captureDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "raw_capture");
        if (!Directory.Exists(captureDir))
        {
            System.Console.WriteLine($"[ERROR] No captures at {captureDir}");
            return;
        }

        var files = Directory.GetFiles(captureDir, "*.bin");
        Array.Sort(files);
        System.Console.WriteLine($"=== Replay Test ===");
        System.Console.WriteLine($"Target: 127.0.0.1:{port}");
        System.Console.WriteLine($"Capture files: {files.Length}");
        System.Console.WriteLine();

        using var socket = new UdpClient();
        var target = new IPEndPoint(IPAddress.Loopback, port);
        socket.Client.ReceiveTimeout = 1000; // 1s timeout

        int sent = 0;
        int responses = 0;

        for (int i = 0; i < Math.Min(10, files.Length); i++)
        {
            var data = File.ReadAllBytes(files[i]);
            socket.Send(data, data.Length, target);
            sent++;

            System.Console.Write($"  [{i + 1}] Sent {Path.GetFileName(files[i])} ({data.Length}B) → ");

            // Check for responses (might get multiple)
            bool gotResponse = false;
            while (true)
            {
                try
                {
                    IPEndPoint? remote = null;
                    var resp = socket.Receive(ref remote);
                    responses++;
                    gotResponse = true;
                    System.Console.WriteLine($"RESPONSE {resp.Length}B!");
                    System.Console.WriteLine($"       Raw: {BitConverter.ToString(resp, 0, Math.Min(32, resp.Length))}");

                    // Try Blowfish decrypt the response
                    try
                    {
                        var cipher = LoLServer.Core.Network.BlowFish.FromBase64("17BLOhi6KZsTtldTsizvHg==");
                        var dec = cipher.Decrypt(resp);
                        System.Console.WriteLine($"       Dec: {BitConverter.ToString(dec, 0, Math.Min(32, dec.Length))}");
                    }
                    catch { }
                }
                catch (SocketException)
                {
                    if (!gotResponse)
                        System.Console.WriteLine("no response (timeout)");
                    break;
                }
            }

            Thread.Sleep(200);
        }

        System.Console.WriteLine();
        System.Console.WriteLine($"=== Results: Sent={sent} Responses={responses} ===");
        if (responses > 0)
            System.Console.WriteLine("[OK] Server is responding to client packets!");
        else
            System.Console.WriteLine("[WARN] No responses received. Protocol might need more work.");
    }
}
