<?php

declare(strict_types = 1);

namespace RTCKit\Pcap;

use InvalidArgumentException;
use RTCKit\Pcap\Frame\GlobalHeader;
use RTCKit\Pcap\Frame\PacketHeader;
use RTCKit\Pcap\Frame\Packet;
use RTCKit\Pcap\Protocol\PcapGlobalHeader;
use RTCKit\Pcap\Protocol\PcapPacketHeader;

/**
 * Pcap data parser
 */
class Reader
{
    /**
     * @input Local machine's endianness
     */
    private int $localEndianness;

    /**
     * @input Input's endianness
     */
    private int $inputEndianness;

    public function __construct()
    {
        $this->localEndianness = Endianness::getLocal();

        /* Assume local endianness; for actual .pcap files, it will be reassessed based on the global header. */
        $this->setInputEndianness($this->localEndianness);
    }

    /**
     * Parses raw binary input into a GlobalHeader object
     *
     * @param string $input
     * @throws InvalidArgumentException
     * @return GlobalHeader
     */
    public function parseGlobalHeader(string $input): GlobalHeader
    {
        $header = PcapGlobalHeader::decode($input, $this->localEndianness);

        $this->setInputEndianness($header->endianness);

        return $header;
    }

    /**
     * Parses raw binary input into a PacketHeader object
     *
     * @param string $input
     * @throws InvalidArgumentException
     * @return PacketHeader
     */
    public function parsePacketHeader(string $input): PacketHeader
    {
        return PcapPacketHeader::decode($input, $this->inputEndianness);
    }

/* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
    /**
     * Parses raw binary input into a Packet object
     *
     * @param string $input
     * @param int $linkType
     * @throws InvalidArgumentException
     * @return Packet
     */
    public function parsePacket(string $input, int $linkType): Packet
    {
        $packet = new Packet;
        $packet->data = $input;

        return $packet;
    }
/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

    /**
     * Sets input's endianness
     *
     * @param int $endianness
     */
    final public function setInputEndianness(int $endianness): void
    {
        $this->inputEndianness = $endianness;
    }
}
