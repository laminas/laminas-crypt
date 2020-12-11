<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric\Padding;

use Laminas\Crypt\Symmetric\Padding\Pkcs7;
use PHPUnit\Framework\TestCase;

class Pkcs7Test extends TestCase
{
    /** @var Pkcs7 */
    public $padding;
    /** @var integer */
    public $start;
    /** @var integer */
    public $end;

    public function setUp(): void
    {
        $this->padding = new Pkcs7();
        $this->start   = 1;
        $this->end     = 32;
    }

    public function testPad()
    {
        for ($blockSize = $this->start; $blockSize <= $this->end; $blockSize++) {
            for ($i = 1; $i <= $blockSize; $i++) {
                $input  = str_repeat(chr(rand(0, 255)), $i);
                $output = $this->padding->pad($input, $blockSize);
                $num    = $blockSize - ($i % $blockSize);
                $this->assertEquals($output, $input . str_repeat(chr($num), $num));
            }
        }
    }

    public function testStrip()
    {
        for ($blockSize = $this->start; $blockSize <= $this->end; $blockSize++) {
            for ($i = 1; $i < $blockSize; $i++) {
                $input  = str_repeat('a', $i);
                $num    = $blockSize - ($i % $blockSize);
                $output = $this->padding->strip($input . str_repeat(chr($num), $num));
                $this->assertEquals($output, $input);
            }
        }
    }
}
