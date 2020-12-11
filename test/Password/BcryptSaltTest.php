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

class BcryptSaltTest extends TestCase
{
    /** @var Bcrypt */
    public $bcrypt;

    /** @var string */
    public $salt;

    /** @var string */
    public $bcryptPassword;

    /** @var string */
    public $password;

    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70000) {
            $this->markTestSkipped(
                sprintf('I cannot execute %s with PHP 7+', __CLASS__)
            );
        }
        $this->bcrypt   = new Bcrypt();
        $this->salt     = '1234567890123456789012';
        $this->password = 'test';
        $this->prefix   = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$123456789012345678901uIcehzOq0s9RvVtyXJFIsuuxuE2XZRMq';
    }

    public function testConstructByOptions()
    {
        $options = [
            'cost' => '15',
            'salt' => $this->salt
        ];
        $bcrypt  = new Bcrypt($options);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    /**
     * This test uses ArrayObject to simulate a Laminas\Config\Config instance;
     * the class itself only tests for Traversable.
     */
    public function testConstructByConfig()
    {
        $options = [
            'cost' => '15',
            'salt' => $this->salt
        ];
        $config  = new ArrayObject($options);
        $bcrypt  = new Bcrypt($config);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    public function testSetSalt()
    {
        $this->bcrypt->setSalt($this->salt);
        $this->assertEquals($this->salt, $this->bcrypt->getSalt());
    }

    public function testSetSmallSalt()
    {
        $this->expectException(Exception\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf(
            'The length of the salt must be at least %d bytes',
            Bcrypt::MIN_SALT_SIZE
        ));
        $this->bcrypt->setSalt('small salt');
    }

    public function testCreateWithSalt()
    {
        $this->bcrypt->setSalt($this->salt);
        $password = $this->bcrypt->create($this->password);
        $this->assertEquals($password, $this->bcryptPassword);
    }

    public function testVerify()
    {
        $this->assertTrue($this->bcrypt->verify($this->password, $this->bcryptPassword));
        $this->assertFalse($this->bcrypt->verify(substr($this->password, -1), $this->bcryptPassword));
    }

    public function testPasswordWith8bitCharacter()
    {
        $password = 'test' . chr(128);
        $this->bcrypt->setSalt($this->salt);

        $this->assertEquals(
            '$2y$10$123456789012345678901uzhRRynEzg8i5sfojdxRRwS90XfVE9vW',
            $this->bcrypt->create($password)
        );
    }
}
