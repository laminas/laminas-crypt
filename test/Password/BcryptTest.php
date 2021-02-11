<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Password;

use ArrayObject;
use Laminas\Crypt\Password\Bcrypt;
use Laminas\Crypt\Password\Exception;
use PHPUnit\Framework\TestCase;

/**
 * @group      Laminas_Crypt
 */
class BcryptTest extends TestCase
{
    /** @var Bcrypt */
    public $bcrypt;

    /** @var string */
    public $bcryptPassword;

    /** @var string */
    public $password;

    public function setUp(): void
    {
        $this->bcrypt   = new Bcrypt();
        $this->password = 'test';
        $this->prefix = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$123456789012345678901uIcehzOq0s9RvVtyXJFIsuuxuE2XZRMq';
    }

    public function testConstructByOptions()
    {
        $options = [ 'cost' => '15' ];
        $bcrypt  = new Bcrypt($options);
        $this->assertEquals('15', $bcrypt->getCost());
    }

    /**
     * This test uses ArrayObject to simulate a Laminas\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig()
    {
        $options = [ 'cost' => '15' ];
        $config  = new ArrayObject($options);
        $bcrypt  = new Bcrypt($config);
        $this->assertEquals('15', $bcrypt->getCost());
    }

    public function testWrongConstruct()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The options parameter must be an array or a Traversable');
        new Bcrypt('test');
    }

    public function testSetCost()
    {
        $this->bcrypt->setCost('16');
        $this->assertEquals('16', $this->bcrypt->getCost());
    }

    public function testSetWrongCost()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage('The cost parameter of bcrypt must be in range 04-31');
        $this->bcrypt->setCost('3');
    }

    public function testCreateWithBuiltinSalt()
    {
        $password = $this->bcrypt->create('test');
        $this->assertNotEmpty($password);
        $this->assertEquals(60, strlen($password));
    }

    public function testVerify()
    {
        $this->assertTrue($this->bcrypt->verify($this->password, $this->bcryptPassword));
        $this->assertFalse($this->bcrypt->verify(substr($this->password, -1), $this->bcryptPassword));
    }

    public function testPasswordWith8bitCharacter()
    {
        $password = 'test' . chr(128);
        $hash = $this->bcrypt->create($password);

        $this->assertNotEmpty($hash);
        $this->assertEquals(60, strlen($hash));
        $this->assertTrue($this->bcrypt->verify($password, $hash));
    }

    /**
     * @requires PHP 7.0
     */
    public function testSetSaltError()
    {
        $this->expectError();
        $this->bcrypt->setSalt('test');
    }

    /**
     * @requires PHP 7.0
     */
    public function testGetSaltError()
    {
        $this->expectError();
        $this->bcrypt->getSalt();
    }

    public function testBenchmarkCost()
    {
        $cost = $this->bcrypt->benchmarkCost();
        $this->assertIsInt($cost);
        $this->assertTrue($cost > 8 && $cost < 32);
    }
}
