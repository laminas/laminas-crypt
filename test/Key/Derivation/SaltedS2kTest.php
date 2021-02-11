<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Key\Derivation;

use Laminas\Crypt\Key\Derivation\Exception;
use Laminas\Crypt\Key\Derivation\SaltedS2k;
use PHPUnit\Framework\TestCase;

/**
 * @group      Laminas_Crypt
 */
class SaltedS2kTest extends TestCase
{
    /** @var string */
    public $salt;

    public function setUp(): void
    {
        $this->salt = '12345678';
    }

    public function testCalc()
    {
        if (! extension_loaded('hash')) {
            $this->markTestSkipped('The hash extension is not available');
            return;
        }

        $password = SaltedS2k::calc('sha256', 'test', $this->salt, 32);
        $this->assertEquals(32, strlen($password));
        $this->assertEquals('qzQISUBUSP1iqYtwe/druhdOVqluc/Y2TetdSHSbaw8=', base64_encode($password));
    }

    public function testCalcWithWrongHash()
    {
        if (! extension_loaded('hash')) {
            $this->markTestSkipped('The hash extension is not available');
            return;
        }

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The hash algorithm wrong is not supported by %s',
            SaltedS2k::class
        ));
        SaltedS2k::calc('wrong', 'test', $this->salt, 32);
    }

    public function testCalcWithWrongSalt()
    {
        if (! extension_loaded('hash')) {
            $this->markTestSkipped('The hash extension is not available');
            return;
        }

        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The salt size must be at least of 8 bytes');
        SaltedS2k::calc('sha256', 'test', substr($this->salt, -1), 32);
    }
}
