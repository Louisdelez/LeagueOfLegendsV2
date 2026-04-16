using System;
using System.Collections.Generic;
using System.Text;

namespace LoLServer.Core.Protocol.Packets;

/// <summary>
/// Binary packet writer for LoL game packets.
/// All values are little-endian (LE) to match the LoL client.
/// </summary>
public class PacketWriter
{
    private readonly List<byte> _buffer = new();

    public int Length => _buffer.Count;
    public byte[] ToArray() => _buffer.ToArray();

    public PacketWriter WriteByte(byte value)
    {
        _buffer.Add(value);
        return this;
    }

    public PacketWriter WriteBytes(byte[] data)
    {
        _buffer.AddRange(data);
        return this;
    }

    public PacketWriter WriteBool(bool value)
    {
        _buffer.Add(value ? (byte)1 : (byte)0);
        return this;
    }

    public PacketWriter WriteInt16(short value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    public PacketWriter WriteUInt16(ushort value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    public PacketWriter WriteInt32(int value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    public PacketWriter WriteUInt32(uint value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    public PacketWriter WriteFloat(float value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    public PacketWriter WriteUInt64(ulong value)
    {
        _buffer.AddRange(BitConverter.GetBytes(value));
        return this;
    }

    /// <summary>
    /// Write a fixed-length string (null-padded to size).
    /// </summary>
    public PacketWriter WriteFixedString(string value, int size)
    {
        var bytes = Encoding.ASCII.GetBytes(value ?? "");
        var padded = new byte[size];
        Array.Copy(bytes, padded, Math.Min(bytes.Length, size - 1));
        _buffer.AddRange(padded);
        return this;
    }

    /// <summary>
    /// Write a null-terminated string.
    /// </summary>
    public PacketWriter WriteNullTermString(string value)
    {
        _buffer.AddRange(Encoding.UTF8.GetBytes(value ?? ""));
        _buffer.Add(0);
        return this;
    }

    /// <summary>
    /// Write a LoL NetID (uint32).
    /// </summary>
    public PacketWriter WriteNetId(uint netId) => WriteUInt32(netId);

    /// <summary>
    /// Write padding bytes (zeros).
    /// </summary>
    public PacketWriter WritePad(int count)
    {
        for (int i = 0; i < count; i++)
            _buffer.Add(0);
        return this;
    }

    /// <summary>
    /// Write a 3D position (X, Y, Z as floats).
    /// </summary>
    public PacketWriter WritePosition(float x, float y, float z)
    {
        WriteFloat(x);
        WriteFloat(y);
        WriteFloat(z);
        return this;
    }

    /// <summary>
    /// Start a packet with opcode.
    /// </summary>
    public static PacketWriter Create(GamePacketId opcode)
    {
        var w = new PacketWriter();
        w.WriteByte((byte)opcode);
        return w;
    }

    public static PacketWriter Create(LoadScreenPacketId opcode)
    {
        var w = new PacketWriter();
        w.WriteByte((byte)opcode);
        return w;
    }

    /// <summary>
    /// Start a packet with opcode + senderNetId (most S2C packets).
    /// </summary>
    public static PacketWriter CreateWithSender(GamePacketId opcode, uint senderNetId)
    {
        var w = new PacketWriter();
        w.WriteByte((byte)opcode);
        w.WriteNetId(senderNetId);
        return w;
    }
}

/// <summary>
/// Binary packet reader for LoL game packets.
/// </summary>
public class PacketReader
{
    private readonly byte[] _data;
    private int _pos;

    public PacketReader(byte[] data)
    {
        _data = data;
        _pos = 0;
    }

    public int Position => _pos;
    public int Remaining => _data.Length - _pos;
    public int Length => _data.Length;

    public byte ReadByte() => _data[_pos++];

    public byte[] ReadBytes(int count)
    {
        var result = new byte[count];
        Array.Copy(_data, _pos, result, 0, count);
        _pos += count;
        return result;
    }

    public bool ReadBool() => ReadByte() != 0;

    public short ReadInt16()
    {
        var val = BitConverter.ToInt16(_data, _pos);
        _pos += 2;
        return val;
    }

    public ushort ReadUInt16()
    {
        var val = BitConverter.ToUInt16(_data, _pos);
        _pos += 2;
        return val;
    }

    public int ReadInt32()
    {
        var val = BitConverter.ToInt32(_data, _pos);
        _pos += 4;
        return val;
    }

    public uint ReadUInt32()
    {
        var val = BitConverter.ToUInt32(_data, _pos);
        _pos += 4;
        return val;
    }

    public float ReadFloat()
    {
        var val = BitConverter.ToSingle(_data, _pos);
        _pos += 4;
        return val;
    }

    public ulong ReadUInt64()
    {
        var val = BitConverter.ToUInt64(_data, _pos);
        _pos += 8;
        return val;
    }

    public string ReadFixedString(int size)
    {
        var bytes = ReadBytes(size);
        int end = Array.IndexOf(bytes, (byte)0);
        if (end < 0) end = size;
        return Encoding.ASCII.GetString(bytes, 0, end);
    }

    public string ReadNullTermString()
    {
        int start = _pos;
        while (_pos < _data.Length && _data[_pos] != 0)
            _pos++;
        var str = Encoding.UTF8.GetString(_data, start, _pos - start);
        if (_pos < _data.Length) _pos++; // skip null
        return str;
    }

    public uint ReadNetId() => ReadUInt32();

    public void Skip(int count) => _pos += count;
}
