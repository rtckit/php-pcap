<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Frame;

use RTCKit\Pcap\Endianness;

/**
 * Pcap Global Header Model
 *
 * https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header
 */
class GlobalHeader
{
    /**
     * @var int Global header's binary length in bytes
     */
    public const BINARY_LENGTH = 24;

    /**
     * @var int Pcap magic number read if written in local endianness
     */
    public const MAGIC_SAME_ENDIANNESS = 0xa1b2c3d4;

    /**
     * @var int Pcap magic number read if written in reverse endianness
     */
    public const MAGIC_SWAP_ENDIANNESS = 0xd4c3b2a1;

    /**
     * @var int Contemporary Pcap format major version number
     */
    public const PCAP_VERSION_MAJOR = 2;

    /**
     * @var int Contemporary Pcap format minor version number
     */
    public const PCAP_VERSION_MINOR = 4;

    /**
     * @var array Unpack global header formats relative to endianness
     */
    public const UNPACK_FORMAT = [
        Endianness::LITTLE => 'vversionMajor/vversionMinor/VthisZone/VsigFigs/VsnapLen/VlinkType',
        Endianness::BIG => 'nversionMajor/nversionMinor/NthisZone/NsigFigs/NsnapLen/NlinkType',
    ];

    /**
     * @var array Pack global header formats relative to endianness
     */
    public const PACK_FORMAT = [
        Endianness::LITTLE => 'vvVVVV',
        Endianness::BIG => 'nnNNNN',
    ];

    /**
     * @var int Detected endianness
     */
    public int $endianness;

    /*
     * Global header properties modeled after libpcap's pcap_file_header
     * https://github.com/the-tcpdump-group/libpcap/blob/b05701eea47342742aee331925b2a0f4d0a426b0/pcap/pcap.h#L207-L215
     */

    /**
     * @var int Magic number
     */
    public ?int $magic = null;

    /**
     * @var int Major version number
     */
    public ?int $versionMajor = null;

    /**
     * @var int Minor version number
     */
    public ?int $versionMinor = null;

    /**
     * @var int GMT to local correction
     */
    public ?int $thisZone = null;

    /**
     * @var int Accuracy of timestamps
     */
    public ?int $sigFigs = null;

    /**
     * @var int Maximum length of captured packets, in bytes
     */
    public ?int $snapLen = null;

    /**
     * @var int Data link type
     */
    public ?int $linkType = null;
}
