<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Key\Derivation;

use Laminas\Crypt\Key\Derivation\SaltedS2k;

/**
 * @group      Laminas_Crypt
 */
class SaltedS2kTest extends \PHPUnit_Framework_TestCase
{
    /** @var string */
    public $salt;

    public function setUp()
    {
        $this->salt = '12345678';
    }

    public function testCalc()
    {
        if (!extension_loaded('mhash')) {
            $this->markTestSkipped('The mhash extension is not available');
            return;
        }
        $password = SaltedS2k::calc('sha256', 'test', $this->salt, 32);
        $this->assertEquals(32, strlen($password));
        $this->assertEquals('qzQISUBUSP1iqYtwe/druhdOVqluc/Y2TetdSHSbaw8=', base64_encode($password));
    }

    public function testCalcWithWrongHash()
    {
        if (!extension_loaded('mhash')) {
            $this->markTestSkipped('The mhash extension is not available');
            return;
        }
        $this->setExpectedException('Laminas\Crypt\Key\Derivation\Exception\InvalidArgumentException',
                                    'The hash algorithm wrong is not supported by Laminas\Crypt\Key\Derivation\SaltedS2k');
        $password = SaltedS2k::calc('wrong', 'test', $this->salt, 32);
    }

    public function testCalcWithWrongSalt()
    {
        if (!extension_loaded('mhash')) {
            $this->markTestSkipped('The mhash extension is not available');
            return;
        }
        $this->setExpectedException('Laminas\Crypt\Key\Derivation\Exception\InvalidArgumentException',
                                    'The salt size must be at least of 8 bytes');
        $password = SaltedS2k::calc('sha256', 'test', substr($this->salt,-1), 32);
    }
}
