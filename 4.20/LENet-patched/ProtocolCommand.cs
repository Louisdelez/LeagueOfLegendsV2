namespace LENet
{
    public enum ProtocolCommand
    {
        NONE = 0x00,
        ACKNOWLEDGE = 0x01,
        CONNECT = 0x02,
        VERIFY_CONNECT = 0x03,
        DISCONNECT = 0x04,
        PING = 0x05,
        SEND_RELIABLE = 0x06,
        SEND_UNRELIABLE = 0x07,
        SEND_FRAGMENT = 0x08,
        SEND_UNSEQUENCED = 0x09,
        BANDWIDTH_LIMIT = 0x0A,
        THROTTLE_CONFIGURE = 0x0B,
    }
}
