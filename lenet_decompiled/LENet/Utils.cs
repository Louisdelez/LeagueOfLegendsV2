using System.Net;
using System.Net.Sockets;

namespace LENet;

internal static class Utils
{
	public static bool TimeLess(uint a, uint b)
	{
		return a - b >= 86400000;
	}

	public static uint TimeDiff(uint a, uint b)
	{
		return TimeLess(a, b) ? (b - a) : (a - b);
	}

	public static int WaitReceive(this Socket socket, ref bool condition, uint timeout)
	{
		if (!condition)
		{
			return 0;
		}
		try
		{
			condition = socket.Poll((int)(timeout * 1000), SelectMode.SelectRead);
			return 0;
		}
		catch (SocketException)
		{
			return -1;
		}
	}

	public static int ReceiveFrom(this Socket socket, ref Address receivedAddres, Buffer buffer)
	{
		EndPoint remoteEP = new IPEndPoint(receivedAddres.Host, receivedAddres.Port);
		int num;
		try
		{
			num = socket.ReceiveFrom(buffer.Data, ref remoteEP);
		}
		catch (SocketException ex)
		{
			if (ex.SocketErrorCode != SocketError.WouldBlock && ex.SocketErrorCode != SocketError.ConnectionReset)
			{
				return -1;
			}
			return 0;
		}
		if (num == 0)
		{
			return 0;
		}
		buffer.Position = 0u;
		buffer.DataLength = (uint)num;
		receivedAddres = new Address(remoteEP as IPEndPoint);
		return num;
	}

	public static int SendTo(this Socket socket, Address address, byte[] data, uint offset, uint length)
	{
		IPEndPoint remoteEP = new IPEndPoint(address.Host, address.Port);
		int result;
		try
		{
			result = socket.SendTo(data, (int)offset, (int)length, SocketFlags.None, remoteEP);
		}
		catch (SocketException ex)
		{
			if (ex.SocketErrorCode == SocketError.WouldBlock)
			{
				return 0;
			}
			return -1;
		}
		return result;
	}

	public static byte Clamp(byte v, byte min, byte max)
	{
		return (v > max) ? max : ((v < min) ? min : v);
	}

	public static ushort Clamp(ushort v, ushort min, ushort max)
	{
		return (v > max) ? max : ((v < min) ? min : v);
	}

	public static uint Clamp(uint v, uint min, uint max)
	{
		return (v > max) ? max : ((v < min) ? min : v);
	}
}
