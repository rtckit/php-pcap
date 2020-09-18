<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Frame;

class Packet
{
    public ?AbstractLink $linkFrame = null;

    public ?AbstractNetwork $networkFrame = null;

    public ?AbstractTransport $transportFrame = null;

    public ?string $data = null;
}
