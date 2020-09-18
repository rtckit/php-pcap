<?php

declare(strict_types = 1);

namespace RTCKit\Pcap\Protocol;

use InvalidArgumentException;
use RTCKit\Pcap\Endianness;
use RTCKit\Pcap\Frame\GlobalHeader;

class PcapGlobalHeaderTest extends \PHPUnit\Framework\TestCase
{
    public const VALID_INPUT = "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00";
    public const INVALID_MAGIC = "\xf0\xc3\xb2\xa1\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    /**
     * @test
     */
    public function shouldExhibitReciprocalFunctionality(): void
    {
        $header = new GlobalHeader;

        $header->endianness = Endianness::getLocal();
        $header->magic = GlobalHeader::MAGIC_SAME_ENDIANNESS;
        $header->versionMajor = GlobalHeader::PCAP_VERSION_MAJOR;
        $header->versionMinor = GlobalHeader::PCAP_VERSION_MINOR;
        $header->thisZone = 0;
        $header->sigFigs = 0;
        $header->snapLen = 1024;
        $header->linkType = 1;

        $str = PcapGlobalHeader::encode($header);

        $this->assertNotNull($str);
        $this->assertIsString($str);
        $this->assertEquals(GlobalHeader::BINARY_LENGTH, strlen($str));

        $decoded = PcapGlobalHeader::decode($str, Endianness::getLocal());

        $this->assertNotNull($header);
        $this->assertInstanceOf(GlobalHeader::class, $header);

        $this->assertSame($header->magic, $decoded->magic);
        $this->assertSame($header->versionMajor, $decoded->versionMajor);
        $this->assertSame($header->versionMinor, $decoded->versionMinor);
        $this->assertSame($header->thisZone, $decoded->thisZone);
        $this->assertSame($header->sigFigs, $decoded->sigFigs);
        $this->assertSame($header->snapLen, $decoded->snapLen);
        $this->assertSame($header->linkType, $decoded->linkType);
    }

    /**
     * @test
     */
    public function shouldDecodeValidInput(): void
    {
        $header = PcapGlobalHeader::decode(self::VALID_INPUT, Endianness::LITTLE);

        $this->assertNotNull($header);
        $this->assertInstanceOf(GlobalHeader::class, $header);

        $this->assertEquals(GlobalHeader::PCAP_VERSION_MAJOR, $header->versionMajor);
        $this->assertEquals(GlobalHeader::PCAP_VERSION_MINOR, $header->versionMinor);

        $this->assertIsNumeric($header->thisZone);
        $this->assertIsNumeric($header->sigFigs);
        $this->assertIsNumeric($header->snapLen);
        $this->assertIsNumeric($header->linkType);
    }

    /**
     * @test
     */
    public function shouldNotDecodeInvalidLength(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PcapGlobalHeader::decode('DefinitelyNot24Bytes', Endianness::LITTLE);
    }

    /**
     * @test
     */
    public function shouldNotDecodeInvalidMagic(): void
    {
        $this->expectException(InvalidArgumentException::class);

        PcapGlobalHeader::decode(self::INVALID_MAGIC);
    }

    /**
     * @test
     */
    public function shouldEncodeValidInput(): void
    {
        $header = new GlobalHeader;

        $header->endianness = Endianness::LITTLE;
        $header->versionMajor = GlobalHeader::PCAP_VERSION_MAJOR;
        $header->versionMinor = GlobalHeader::PCAP_VERSION_MINOR;
        $header->thisZone = 0;
        $header->sigFigs = 0;
        $header->snapLen = 4096;
        $header->linkType = 1;

        $str = PcapGlobalHeader::encode($header);

        $this->assertNotNull($str);
        $this->assertIsString($str);
        $this->assertEquals(GlobalHeader::BINARY_LENGTH, strlen($str));
        $this->assertEquals(
            "\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x01\x00\x00\x00",
            $str
        );
    }

    /**
     * @test
     */
    public function shouldNotEncodeInputWithoutEndianness(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $header = new GlobalHeader;

        $header->versionMajor = GlobalHeader::PCAP_VERSION_MAJOR;
        $header->versionMinor = GlobalHeader::PCAP_VERSION_MINOR;
        $header->thisZone = 0;
        $header->sigFigs = 0;
        $header->snapLen = 4096;
        $header->linkType = 1;

        $str = PcapGlobalHeader::encode($header);
    }
}
