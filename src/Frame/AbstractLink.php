<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Frame;

abstract class AbstractLink
{
    /**
     * IEEE 802.3 Ethernet encapsulation
     * https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
     *
     * @int DLT_EN10MB
     */
    public const LINKTYPE_ETHERNET = 1;

    /**
     * Linux "cooked" capture encapsulation
     * https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
     *
     * @int DLT_LINUX_SLL
     */
    public const LINKTYPE_LINUX_SLL = 113;

    /**
     * @var array Link type IDs mapped against their respective classes
     */
    public const LINKTYPES = [
        self::LINKTYPE_ETHERNET => Ethernet::class,
        self::LINKTYPE_LINUX_SLL => Linux::class,
    ];

    /**
     * @var ?Packet Raw packet which encapsulates this frame
     */
    public ?Packet $packet = null;
}
