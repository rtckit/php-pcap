<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Protocol;

use InvalidArgumentException;
use RTCKit\Pcap\Endianness;
use RTCKit\Pcap\Frame\PacketHeader;

class PcapPacketHeaderTest extends \PHPUnit\Framework\TestCase
{
    public const VALID_INPUT = "\x82\xba\x5b\x5f\x5f\xaa\x0e\x00\x62\x00\x00\x00\x62\x00\x00\x00";

    /**
     * @test
     */
    public function shouldExhibitReciprocalFunctionality(): void
    {
        $header = new PacketHeader;
        $now = microtime(true);

        $header->endianness = Endianness::getLocal();
        $header->tsSec = (int)floor($now);
        $header->tsUsec = (int)(($now - $header->tsSec) * 10^6);
        $header->capLen = 1024;
        $header->len = 1024;

        $str = PcapPacketHeader::encode($header);

        $this->assertNotNull($str);
        $this->assertIsString($str);
        $this->assertEquals(PacketHeader::BINARY_LENGTH, strlen($str));

        $decoded = PcapPacketHeader::decode($str, Endianness::getLocal());

        $this->assertNotNull($header);
        $this->assertInstanceOf(PacketHeader::class, $header);

        $this->assertSame($header->tsSec, $decoded->tsSec);
        $this->assertSame($header->tsUsec, $decoded->tsUsec);
        $this->assertSame($header->capLen, $decoded->capLen);
        $this->assertSame($header->len, $decoded->len);
    }

    /**
     * @test
     */
    public function shouldDecodeValidInput(): void
    {
        $header = PcapPacketHeader::decode(self::VALID_INPUT, Endianness::LITTLE);

        $this->assertNotNull($header);
        $this->assertInstanceOf(PacketHeader::class, $header);

        $this->assertIsNumeric($header->tsSec);
        $this->assertIsNumeric($header->tsUsec);
        $this->assertIsNumeric($header->capLen);
        $this->assertIsNumeric($header->len);
    }

    /**
     * @test
     */
    public function shouldNotDecodeInvalidLength(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PcapPacketHeader::decode('DefinitelyNot16Bytes', Endianness::LITTLE);
    }

    /**
     * @test
     */
    public function shouldEncodeValidInput(): void
    {
        $header = new PacketHeader;

        $header->endianness = Endianness::LITTLE;
        $header->tsSec = 1600458579;
        $header->tsUsec = 318272;
        $header->capLen = 2048;
        $header->len = 4096;

        $str = PcapPacketHeader::encode($header);

        $this->assertNotNull($str);
        $this->assertIsString($str);
        $this->assertEquals(PacketHeader::BINARY_LENGTH, strlen($str));
        $this->assertEquals(
            "\x53\x0f\x65\x5f\x40\xdb\x04\x00\x00\x08\x00\x00\x00\x10\x00\x00",
            $str
        );
    }

    /**
     * @test
     */
    public function shouldNotEncodeInputWithoutEndianness(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $header = new PacketHeader;

        $header->tsSec = 1600458579;
        $header->tsUsec = 318272;
        $header->capLen = 2048;
        $header->len = 4096;

        $str = PcapPacketHeader::encode($header);
    }
}
