<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Frame;

use RTCKit\Pcap\Endianness;

/**
 * Pcap Packet Header Model
 *
 * https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header
 */
class PacketHeader
{
    /**
     * @var int Packet header's binary length in bytes
     */
    public const BINARY_LENGTH = 16;

    /**
     * @var array Unpack packet header formats relative to endianness
     */
    public const UNPACK_FORMAT = [
        Endianness::LITTLE => 'VtsSec/VtsUsec/VcapLen/Vlen',
        Endianness::BIG => 'NtsSec/NtsUsec/NcapLen/Nlen',
    ];

    /**
     * @var array Pack packet header formats relative to endianness
     */
    public const PACK_FORMAT = [
        Endianness::LITTLE => 'VVVV',
        Endianness::BIG => 'NNNN',
    ];

    /**
     * @var int Detected endianness
     */
    public int $endianness;

    /*
     * Packet header properties modeled after libpcap's pcap_pkthdr
     * https://github.com/the-tcpdump-group/libpcap/blob/b05701eea47342742aee331925b2a0f4d0a426b0/pcap/pcap.h#L207-L215
     */

    /**
     * @var int Timestamp in seconds
     */
    public ?int $tsSec = null;

    /**
     * @var int Timestamp remainder in microseconds
     */
    public ?int $tsUsec = null;

    /**
     * @var int Length of captured portion
     */
    public ?int $capLen = null;

    /**
     * @var int Packet's original length
     */
    public ?int $len = null;
}
