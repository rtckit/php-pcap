<?php

declare(strict_types = 1);

namespace RTCKit\Pcap;

abstract class LinkPacket
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
}
