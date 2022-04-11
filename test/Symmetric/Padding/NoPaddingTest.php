<?php

namespace LaminasTest\Crypt\Symmetric\Padding;

use Laminas\Crypt\Symmetric\Padding\NoPadding;
use PHPUnit\Framework\TestCase;

class NoPaddingTest extends TestCase
{
    /** @var NoPadding */
    protected $padding;

    public function setUp(): void
    {
        $this->padding = new NoPadding();
    }

    public function testPad()
    {
        $string = 'test';
        for ($size = 0; $size < 10; $size++) {
            $this->assertEquals($string, $this->padding->pad($string, $size));
        }
    }

    public function testStrip()
    {
        $string = 'test';
        $this->assertEquals($string, $this->padding->strip($string));
    }
}
