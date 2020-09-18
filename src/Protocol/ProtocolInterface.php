<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Protocol;

interface ProtocolInterface
{
    public static function decode(string $input): object;

    public static function encode(object $input): string;
}
