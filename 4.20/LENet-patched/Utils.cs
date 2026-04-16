using System.Net.Sockets;
using System.Net;

namespace LENet
{
    internal static class Utils
    {
        public static bool TimeLess(uint a, uint b) 
        { 
            return a - b >= 86400000u;
        }

        public static uint TimeDiff(uint a, uint b) 
        { 
            return TimeLess(a, b) ? b - a : a - b; 
        }

        public static int WaitReceive(this Socket socket, ref bool condition, uint timeout)
        {
            if(condition == false)
            {
                return 0;
            }

            try
            {
                condition = socket.Poll((int)timeout * 1000, SelectMode.SelectRead);
                return 0;
            }
            catch(SocketException)
            {
                return -1;
            }
        }

        public static int ReceiveFrom(this Socket socket, ref Address receivedAddres, Buffer buffer)
        {
            int receivedLength;
            var endPoint = new IPEndPoint(receivedAddres.Host, receivedAddres.Port) as EndPoint;

            try
            {
                receivedLength = socket.ReceiveFrom(buffer.Data, ref endPoint);
            }
            catch(SocketException error)
            {
                if (error.SocketErrorCode != SocketError.WouldBlock && error.SocketErrorCode != SocketError.ConnectionReset)
                {
                    return -1;
                }

                return 0;
            }
            
            if(receivedLength == 0)
            {
                return 0;
            }

            buffer.Position = 0;
            buffer.DataLength = (uint)receivedLength;
            receivedAddres = new Address(endPoint as IPEndPoint);
            return receivedLength;
        }

        public static int SendTo(this Socket socket, Address address, byte[] data, uint offset, uint length)
        {
            int sentLength;
            var endpoint = new IPEndPoint(address.Host, address.Port);

            try
            {
                sentLength = socket.SendTo(data, (int)offset, (int)(length), SocketFlags.None, endpoint);
            }
            catch(SocketException error)
            {
                if(error.SocketErrorCode == SocketError.WouldBlock)
                {
                    return 0;
                }
                return -1;
            }

            return sentLength;
        }

        public static byte Clamp(byte v, byte min, byte max)
        {
            return v > max ? max : v < min ? min : v;
        }

        public static ushort Clamp(ushort v, ushort min, ushort max)
        {
            return v > max ? max : v < min ? min : v;
        }

        public static uint Clamp(uint v, uint min, uint max)
        {
            return v > max ? max : v < min ? min : v;
        }
    }
}
