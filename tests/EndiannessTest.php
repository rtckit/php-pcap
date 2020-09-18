<?php

declare(strict_types = 1);

namespace RTCKit\Pcap;

class EndiannessTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     */
    public function shouldDetermineLocalEndianness()
    {
        $expected = null;
        $arch = php_uname('m');

        switch ($arch) {
            case 'x86_64':
            case 'armv7l':
                $expected = Endianness::LITTLE;
                break;

            default:
                $this->fail('Unknown architecture: ' . $arch);
        }

        $this->assertSame($expected, Endianness::getLocal());
    }
}
