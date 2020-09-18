<?php

declare(strict_types = 1);

namespace RTCKit\Pcap;

use InvalidArgumentException;
use RTCKit\Pcap\Frame\AbstractLink;
use RTCKit\Pcap\Frame\GlobalHeader;
use RTCKit\Pcap\Frame\PacketHeader;

class ReaderTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     */
    public function shouldParseValidGlobalHeader()
    {
        $fp = fopen(__DIR__ . '/fixtures/eth_ipv4_icmp_ping.pcap', 'r');
        $hdr = fread($fp, GlobalHeader::BINARY_LENGTH);

        $reader = new Reader;
        $header = $reader->parseGlobalHeader($hdr);

        $this->assertNotNull($header);
        $this->assertInstanceOf(GlobalHeader::class, $header);

        $this->assertEquals(GlobalHeader::PCAP_VERSION_MAJOR, $header->versionMajor);
        $this->assertEquals(GlobalHeader::PCAP_VERSION_MINOR, $header->versionMinor);

        $this->assertIsNumeric($header->thisZone);
        $this->assertIsNumeric($header->sigFigs);
        $this->assertIsNumeric($header->snapLen);

        $this->assertEquals(AbstractLink::LINKTYPE_ETHERNET, $header->linkType);

        fclose($fp);
    }

    /**
     * @test
     */
    public function shouldNotParseInvalidGlobalHeader()
    {
        $fp = fopen(__DIR__ . '/fixtures/null_global_header.pcap', 'r');
        $hdr = fread($fp, GlobalHeader::BINARY_LENGTH);

        $this->expectException(InvalidArgumentException::class);

        $reader = new Reader;
        $header = $reader->parseGlobalHeader($hdr);

        $this->assertNull($header);

        fclose($fp);
    }

    /**
     * @test
     */
    public function shouldNotParseInvalidGlobalHeaderLength()
    {
        $this->expectException(InvalidArgumentException::class);

        $reader = new Reader;
        $header = $reader->parseGlobalHeader('0123456789abcdef');

        $this->assertNull($header);
    }

    /**
     * @test
     */
    public function shouldParseValidPacketHeaders()
    {
        $fp = fopen(__DIR__ . '/fixtures/eth_ipv4_icmp_ping.pcap', 'r');
        fread($fp, GlobalHeader::BINARY_LENGTH); /* We don't care for the global header */

        $reader = new Reader;

        while (!feof($fp) && ($hdr = fread($fp, PacketHeader::BINARY_LENGTH))) {
            $header = $reader->parsePacketHeader($hdr);

            $this->assertNotNull($header);
            $this->assertInstanceOf(PacketHeader::class, $header);

            $this->assertNotNull($header->tsSec);
            $this->assertNotNull($header->tsUsec);
            $this->assertNotNull($header->capLen);
            $this->assertNotNull($header->len);

            $this->assertGreaterThanOrEqual($header->capLen, $header->len);

            $pkt = fread($fp, $header->capLen); /* We also don't care about the packet */
        }

        fclose($fp);
    }

    /**
     * @test
     */
    public function shouldNotParseInvalidPacketHeaderLength()
    {
        $this->expectException(InvalidArgumentException::class);

        $reader = new Reader;
        $header = $reader->parsePacketHeader('0123456789');

        $this->assertNull($header);
    }

    /**
     * @test
     */
    public function shouldParseValidPackets()
    {
        $fp = fopen(__DIR__ . '/fixtures/eth_ipv4_icmp_ping.pcap', 'r');
        $reader = new Reader;

        $global = $reader->parseGlobalHeader(fread($fp, GlobalHeader::BINARY_LENGTH));

        while (!feof($fp) && ($hdr = fread($fp, PacketHeader::BINARY_LENGTH))) {
            $header = $reader->parsePacketHeader($hdr);
            $packet = $reader->parsePacket(fread($fp, $header->capLen), $global->linkType);

            $this->assertNotNull($packet);
        }

        fclose($fp);
    }
}
