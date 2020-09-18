<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Protocol;

use InvalidArgumentException;
use RTCKit\Pcap\Endianness;
use RTCKit\Pcap\Frame\PacketHeader;

class PcapPacketHeader implements ProtocolInterface
{
    public static function decode(string $input, int $inputEndianness = Endianness::LITTLE): PacketHeader
    {
        if (strlen($input) !== PacketHeader::BINARY_LENGTH) {
            throw new InvalidArgumentException('Invalid packet header binary length');
        }

        $unpacked = unpack(PacketHeader::UNPACK_FORMAT[$inputEndianness], $input);
        $output = new PacketHeader;

        $output->endianness = $inputEndianness;
        $output->tsSec = $unpacked['tsSec'];
        $output->tsUsec = $unpacked['tsUsec'];
        $output->capLen = $unpacked['capLen'];
        $output->len = $unpacked['len'];

        return $output;
    }

    public static function encode(object $input): string
    {
        if (!is_a($input, PacketHeader::class)) {
            throw new InvalidArgumentException('Cannot encode object of class ' . get_class($input));
        }

        if (!isset($input->endianness)) {
            throw new InvalidArgumentException('PacketHeader object does not have endianness set');
        }

        return pack(
            PacketHeader::PACK_FORMAT[$input->endianness],
            $input->tsSec,
            $input->tsUsec,
            $input->capLen,
            $input->len,
        );
    }
}
