<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Password;

use ArrayObject;
use Laminas\Crypt\Password\Bcrypt;
use Laminas\Crypt\Password\BcryptSha;
use Laminas\Crypt\Password\Exception;
use PHPUnit\Framework\TestCase;

/**
 * @group      Laminas_Crypt
 */
class BcryptShaSaltTest extends TestCase
{
    /** @var Bcrypt */
    private $bcrypt;

    /** @var string */
    private $salt;

    /** @var string */
    private $bcryptPassword;

    /** @var string */
    private $password;

    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70000) {
            $this->markTestSkipped(
                sprintf('I cannot execute %s with PHP 7+', __CLASS__)
            );
        }
        $this->bcrypt   = new BcryptSha();
        $this->salt     = '1234567890123456789012';
        $this->password = 'test';
        $this->prefix   = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$123456789012345678901uhQoed..kXLQz0DxloSzgbQaEOW4N2Vm';
    }

    public function testConstructByOptions()
    {
        $options = [
            'cost' => '15',
            'salt' => $this->salt,
        ];
        $bcrypt  = new BcryptSha($options);
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
            'salt' => $this->salt,
        ];
        $config  = new ArrayObject($options);
        $bcrypt  = new BcryptSha($config);
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
            '$2y$10$123456789012345678901uVgYiYiIUd6NpaVJF/AY/uluM1ED.cUq',
            $this->bcrypt->create($password)
        );
    }
}
