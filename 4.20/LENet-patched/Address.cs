using System;
using System.Net;

namespace LENet
{
    public struct Address
    {
        public const uint Any = 0u;

        public const uint Broadcast = 0xFFFFFFFF;
        public uint Host { get; set; }
        public ushort Port { get; set; }

        public IPEndPoint IPEndPoint => new IPEndPoint(Host, Port);

        public Address(IPEndPoint ipEndPoint)
        {
            Host = (uint)ipEndPoint.Address.Address;
            Port = (ushort)ipEndPoint.Port;
        }

        public Address(uint host, ushort port)  
        {
            Host = host;
            Port = port;
        }
        
        public Address(string host, ushort port)
        {
            Host = (uint)IPAddress.Parse(host).Address;
            Port = port;
        }
    }
}
