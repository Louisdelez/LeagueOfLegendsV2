using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace LoLServer.Core.Network;

/// <summary>
/// Fake League Client Update (LCU) server.
/// The LoL game client connects to this via WSS (WebSocket Secure) on the RiotClientPort.
/// We need HTTPS/TLS because the client does SSL_connect.
///
/// The LCU provides game session info before the ENet connection starts:
/// - Game roster (players, champions, teams)
/// - Match ID
/// - Map skin
/// - Clock synchronization data
/// </summary>
public class FakeLCU
{
    private TcpListener? _listener;
    private X509Certificate2? _cert;
    private int _port;
    private bool _running;

    public int Port => _port;

    // Shared paths in the repo root so both Console and Launcher can access them
    private static readonly string SharedDir = FindRepoRoot();
    private static readonly string CertPath = Path.Combine(SharedDir, "fakeLcu.crt");
    private static readonly string PfxPath = Path.Combine(SharedDir, "fakeLcu.pfx");
    private static readonly string PortFilePath = Path.Combine(SharedDir, "fakeLcu.port");

    private static string FindRepoRoot()
    {
        // Walk up from the exe directory to find the repo root (has server/ and client-private/)
        var dir = AppContext.BaseDirectory;
        for (int i = 0; i < 10; i++)
        {
            if (Directory.Exists(Path.Combine(dir, "server")) || File.Exists(Path.Combine(dir, "start-server.bat")))
                return dir;
            var parent = Directory.GetParent(dir);
            if (parent == null) break;
            dir = parent.FullName;
        }
        return AppContext.BaseDirectory; // fallback
    }

    public void Start()
    {
        // Try to load existing PFX (signed by our CA), fallback to self-signed
        var customPfx = Path.Combine(SharedDir, "server_tls.pfx");
        if (File.Exists(customPfx))
        {
            _cert = new X509Certificate2(customPfx, "", X509KeyStorageFlags.Exportable);
            System.Console.WriteLine($"[LCU] Using custom cert from {customPfx} (CN={_cert.Subject})");
        }
        else
        {
            _cert = GenerateSelfSignedCert();
            System.Console.WriteLine("[LCU] Using self-signed cert (no server_tls.pfx found)");
        }

        // Export the certificate to PEM and install into the trusted root store
        ExportAndTrustCert(_cert);

        // Find free port
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _running = true;
        var thread = new Thread(AcceptLoop) { IsBackground = true, Name = "FakeLCU" };
        thread.Start();

        // Write port to shared file so the Launcher can read it
        File.WriteAllText(PortFilePath, _port.ToString());

        System.Console.WriteLine($"[LCU] Fake RiotClient (TLS) running on port {_port}");
    }

    /// <summary>
    /// Read the FakeLCU port from a file written by another process.
    /// Returns -1 if not found.
    /// </summary>
    public static int ReadPortFromFile()
    {
        if (File.Exists(PortFilePath))
        {
            var content = File.ReadAllText(PortFilePath).Trim();
            if (int.TryParse(content, out int port) && port > 0)
            {
                System.Console.WriteLine($"[LCU] Using FakeLCU port {port} from {PortFilePath}");
                return port;
            }
        }
        return -1;
    }

    /// <summary>
    /// Exports the certificate to a PEM file on disk, then imports it into the
    /// Windows CurrentUser\Root certificate store so the LoL client trusts it.
    /// </summary>
    private static void ExportAndTrustCert(X509Certificate2 cert)
    {
        // Save as PEM (.crt) for manual import / inspection
        var pemBytes = cert.Export(X509ContentType.Cert);
        var pem = "-----BEGIN CERTIFICATE-----\r\n" +
                  Convert.ToBase64String(pemBytes, Base64FormattingOptions.InsertLineBreaks) +
                  "\r\n-----END CERTIFICATE-----\r\n";
        File.WriteAllText(CertPath, pem);
        System.Console.WriteLine($"[LCU] Certificate saved to {CertPath}");

        // Import into Windows CurrentUser\Root via the .NET X509Store API
        try
        {
            using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Check if cert already exists — skip to avoid Windows prompt
            var existing = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, cert.Subject, false);
            if (existing.Count > 0)
            {
                System.Console.WriteLine("[LCU] Certificate already in store, skipping install");
                store.Close();
                return;
            }

            store.Add(cert);
            store.Close();
            System.Console.WriteLine("[LCU] Certificate installed in CurrentUser\\Root trusted store");
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"[LCU] WARNING: Could not install cert in store: {ex.Message}");
            System.Console.WriteLine($"[LCU] You can manually import it with:");
            System.Console.WriteLine($"[LCU]   certutil -user -addstore Root \"{CertPath}\"");
        }
    }

    private void AcceptLoop()
    {
        while (_running)
        {
            try
            {
                var client = _listener!.AcceptTcpClient();
                ThreadPool.QueueUserWorkItem(_ => HandleClient(client));
            }
            catch (SocketException) when (!_running) { break; }
            catch (Exception ex)
            {
                System.Console.WriteLine($"[LCU] Accept error: {ex.Message}");
            }
        }
    }

    private void HandleClient(TcpClient client)
    {
        try
        {
            using var stream = client.GetStream();
            using var sslStream = new SslStream(stream, false);

            sslStream.AuthenticateAsServer(_cert!, false,
                System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                false);

            System.Console.WriteLine($"[LCU] TLS connection established from {client.Client.RemoteEndPoint}");

            // Read the HTTP/WebSocket upgrade request
            var buffer = new byte[8192];
            int bytesRead = sslStream.Read(buffer, 0, buffer.Length);
            var request = Encoding.UTF8.GetString(buffer, 0, bytesRead);

            System.Console.WriteLine($"[LCU] Request: {request.Split('\n')[0].Trim()}");

            if (request.Contains("Upgrade: websocket", StringComparison.OrdinalIgnoreCase))
            {
                HandleWebSocketUpgrade(sslStream, request);
            }
            else
            {
                // Regular HTTPS request
                HandleHttpRequest(sslStream, request);
            }
        }
        catch (Exception ex)
        {
            System.Console.WriteLine($"[LCU] Client handler error: {ex.Message}");
        }
        finally
        {
            client.Close();
        }
    }

    private void HandleWebSocketUpgrade(SslStream stream, string request)
    {
        // Extract Sec-WebSocket-Key
        string? wsKey = null;
        foreach (var line in request.Split('\n'))
        {
            if (line.StartsWith("Sec-WebSocket-Key:", StringComparison.OrdinalIgnoreCase))
            {
                wsKey = line.Split(':', 2)[1].Trim();
                break;
            }
        }

        if (wsKey == null)
        {
            System.Console.WriteLine("[LCU] No WebSocket key found in upgrade request");
            return;
        }

        // WebSocket handshake response
        var acceptKey = Convert.ToBase64String(
            SHA1.HashData(Encoding.UTF8.GetBytes(wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        );

        var response = $"HTTP/1.1 101 Switching Protocols\r\n" +
                       $"Upgrade: websocket\r\n" +
                       $"Connection: Upgrade\r\n" +
                       $"Sec-WebSocket-Accept: {acceptKey}\r\n\r\n";

        var responseBytes = Encoding.UTF8.GetBytes(response);
        stream.Write(responseBytes, 0, responseBytes.Length);

        System.Console.WriteLine($"[LCU] WebSocket connection established!");

        // Now we're in WebSocket mode - send game session data
        // The client expects JSON messages via WebSocket frames

        // Send initial game data that the client needs before doing ENet Hard Connect
        SendWebSocketMessage(stream, BuildGameFlowData());

        // Keep connection alive and handle incoming WebSocket frames
        try
        {
            var buffer = new byte[4096];
            while (_running)
            {
                int read = stream.Read(buffer, 0, buffer.Length);
                if (read == 0) break;

                // Parse WebSocket frame
                var frameData = DecodeWebSocketFrame(buffer, read);
                if (frameData != null)
                {
                    System.Console.WriteLine($"[LCU] WS received: {Encoding.UTF8.GetString(frameData).Substring(0, Math.Min(200, frameData.Length))}");
                }
            }
        }
        catch (IOException) { } // Client disconnected
    }

    private void HandleHttpRequest(SslStream stream, string request)
    {
        var responseJson = "{}";
        var path = request.Split(' ')[1];

        System.Console.WriteLine($"[LCU] HTTP: {path}");

        if (path.Contains("/riotclient/auth-token"))
            responseJson = "\"PrivateServerToken123\"";
        else if (path.Contains("/region-locale"))
            responseJson = "{\"locale\":\"fr_FR\",\"region\":\"EUW\",\"webLanguage\":\"fr\",\"webRegion\":\"euw\"}";

        var body = Encoding.UTF8.GetBytes(responseJson);
        var httpResponse = $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n";

        stream.Write(Encoding.UTF8.GetBytes(httpResponse));
        stream.Write(body);
    }

    private string BuildGameFlowData()
    {
        // JSON message that mimics what the real LCU sends for game start
        // Based on the real game logs, the client expects:
        // - Game flow session info
        // - Player roster
        // - Match ID
        return @"[8,""OnJsonApiEvent_lol-gameflow_v1_session"",{""data"":{
            ""gameData"":{
                ""gameId"":1,
                ""gameName"":""Private Server"",
                ""isCustomGame"":true,
                ""gameType"":""CUSTOM_GAME"",
                ""mapId"":11,
                ""teamOne"":[{
                    ""championId"":81,
                    ""selectedSkinIndex"":0,
                    ""spell1Id"":4,
                    ""spell2Id"":14,
                    ""summonerId"":1,
                    ""summonerName"":""Player1"",
                    ""teamId"":100
                }],
                ""teamTwo"":[],
                ""playerChampionSelections"":[{
                    ""championId"":81,
                    ""selectedSkinIndex"":0,
                    ""spell1Id"":4,
                    ""spell2Id"":14,
                    ""summonerId"":1
                }]
            },
            ""gameClient"":{
                ""running"":true,
                ""serverIp"":""127.0.0.1"",
                ""serverPort"":5119
            },
            ""phase"":""InProgress""
        }}]";
    }

    private void SendWebSocketMessage(SslStream stream, string message)
    {
        var data = Encoding.UTF8.GetBytes(message);
        var frame = EncodeWebSocketFrame(data);
        stream.Write(frame, 0, frame.Length);
        System.Console.WriteLine($"[LCU] WS sent: {message.Substring(0, Math.Min(100, message.Length))}...");
    }

    private byte[] EncodeWebSocketFrame(byte[] data)
    {
        // Simple WebSocket text frame encoding (server→client, no mask)
        byte[] frame;
        if (data.Length < 126)
        {
            frame = new byte[2 + data.Length];
            frame[0] = 0x81; // FIN + TEXT
            frame[1] = (byte)data.Length;
            Array.Copy(data, 0, frame, 2, data.Length);
        }
        else if (data.Length < 65536)
        {
            frame = new byte[4 + data.Length];
            frame[0] = 0x81;
            frame[1] = 126;
            frame[2] = (byte)((data.Length >> 8) & 0xFF);
            frame[3] = (byte)(data.Length & 0xFF);
            Array.Copy(data, 0, frame, 4, data.Length);
        }
        else
        {
            frame = new byte[10 + data.Length];
            frame[0] = 0x81;
            frame[1] = 127;
            var len = BitConverter.GetBytes((long)data.Length);
            if (BitConverter.IsLittleEndian) Array.Reverse(len);
            Array.Copy(len, 0, frame, 2, 8);
            Array.Copy(data, 0, frame, 10, data.Length);
        }
        return frame;
    }

    private byte[]? DecodeWebSocketFrame(byte[] buffer, int length)
    {
        if (length < 2) return null;

        int payloadLen = buffer[1] & 0x7F;
        bool masked = (buffer[1] & 0x80) != 0;
        int offset = 2;

        if (payloadLen == 126)
        {
            payloadLen = (buffer[2] << 8) | buffer[3];
            offset = 4;
        }
        else if (payloadLen == 127)
        {
            offset = 10;
            payloadLen = (int)BitConverter.ToInt64(buffer, 2);
        }

        byte[]? mask = null;
        if (masked)
        {
            mask = new byte[4];
            Array.Copy(buffer, offset, mask, 0, 4);
            offset += 4;
        }

        if (offset + payloadLen > length) return null;

        var data = new byte[payloadLen];
        Array.Copy(buffer, offset, data, 0, payloadLen);

        if (masked && mask != null)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] ^= mask[i % 4];
        }

        return data;
    }

    private static X509Certificate2 GenerateSelfSignedCert()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Mark as a CA certificate so it can be trusted as a root CA
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));

        // SAN extension — required by modern TLS clients (including LoL's BoringSSL)
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.Parse("127.0.0.1"));
        request.CertificateExtensions.Add(san.Build());

        // Key usage for TLS server
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.KeyCertSign, false));

        // Extended key usage: Server Authentication
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));

        var cert = request.CreateSelfSigned(DateTimeOffset.Now.AddDays(-1), DateTimeOffset.Now.AddYears(5));

        // Export and reimport to make the private key available
        return new X509Certificate2(
            cert.Export(X509ContentType.Pfx, "pass"),
            "pass",
            X509KeyStorageFlags.Exportable);
    }

    public void Stop()
    {
        _running = false;
        _listener?.Stop();
        _cert?.Dispose();
    }
}
