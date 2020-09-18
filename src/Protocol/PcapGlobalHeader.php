<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Protocol;

use InvalidArgumentException;
use RTCKit\Pcap\Endianness;
use RTCKit\Pcap\Frame\GlobalHeader;

class PcapGlobalHeader implements ProtocolInterface
{
    public static function decode(string $input, int $localEndianness = Endianness::LITTLE): GlobalHeader
    {
        if (strlen($input) !== GlobalHeader::BINARY_LENGTH) {
            throw new InvalidArgumentException('Invalid global header binary length');
        }

        $output = new GlobalHeader;
        $output->magic = current(unpack('V', substr($input, 0, 4)));

        switch ($output->magic) {
            case GlobalHeader::MAGIC_SAME_ENDIANNESS:
                $output->endianness = $localEndianness;
                break;

            case GlobalHeader::MAGIC_SWAP_ENDIANNESS:
                $output->endianness = ($localEndianness === Endianness::LITTLE) ? Endianness::BIG : Endianness::LITTLE;
                break;

            default:
                throw new InvalidArgumentException('Unsupported global header magic number');
        }

        $unpacked = unpack(GlobalHeader::UNPACK_FORMAT[$output->endianness], $input, 4);

        $output->versionMajor = $unpacked['versionMajor'];
        $output->versionMinor = $unpacked['versionMinor'];
        $output->thisZone = $unpacked['thisZone'];
        $output->sigFigs = $unpacked['sigFigs'];
        $output->snapLen = $unpacked['snapLen'];
        $output->linkType = $unpacked['linkType'];

        return $output;
    }

    public static function encode(object $input): string
    {
        if (!is_a($input, GlobalHeader::class)) {
            throw new InvalidArgumentException('Cannot encode object of class ' . get_class($input));
        }

        if (!isset($input->endianness)) {
            throw new InvalidArgumentException('GlobalHeader object does not have endianness set');
        }

        return pack(($input->endianness == Endianness::LITTLE) ? 'V' : 'N', GlobalHeader::MAGIC_SAME_ENDIANNESS)
            . pack(
                GlobalHeader::PACK_FORMAT[$input->endianness],
                $input->versionMajor,
                $input->versionMinor,
                $input->thisZone,
                $input->sigFigs,
                $input->snapLen,
                $input->linkType
            );
    }
}
