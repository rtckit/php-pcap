<?php

declare(strict_types = 1);

namespace RTCKit\Pcap;

/**
 * Endianness
 */
final class Endianness
{
    public const LITTLE = 0;
    public const BIG = 1;

    /**
     * Computes endianness of local machine
     *
     * @return int
     */
    public static function getLocal(): int
    {
        $bytes = 0x00FF;
        $packed = pack('S', $bytes);

        return ($bytes === current(unpack('v', $packed))) ? self::LITTLE : self::BIG;
    }
}
