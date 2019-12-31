<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Password;

use Laminas\Config\Config;
use Laminas\Crypt\Password\Bcrypt;
use Laminas\Crypt\Password\BcryptSha;

/**
 * @group      Laminas_Crypt
 */
class BcryptShaTest extends \PHPUnit_Framework_TestCase
{
    /** @var Bcrypt */
    private $bcrypt;
    /** @var string */
    private $salt;
    /** @var string */
    private $bcryptPassword;
    /** @var string */
    private $password;

    public function setUp()
    {
        $this->bcrypt   = new BcryptSha();
        $this->salt     = '1234567890123456';
        $this->password = 'test';
        $this->prefix   = '$2y$';

        $this->bcryptPassword = $this->prefix . '10$MTIzNDU2Nzg5MDEyMzQ1NeqZGfIabq2.v6vX10KI4/z0pMoIoDyVa';
    }

    public function testConstructByOptions()
    {
        $options = [
            'cost'       => '15',
            'salt'       => $this->salt
        ];
        $bcrypt  = new BcryptSha($options);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    public function testConstructByConfig()
    {
        $options = [
            'cost'       => '15',
            'salt'       => $this->salt
        ];
        $config  = new Config($options);
        $bcrypt  = new BcryptSha($config);
        $this->assertEquals('15', $bcrypt->getCost());
        $this->assertEquals($this->salt, $bcrypt->getSalt());
    }

    public function testWrongConstruct()
    {
        $this->setExpectedException('Laminas\Crypt\Password\Exception\InvalidArgumentException',
                                    'The options parameter must be an array or a Traversable');
        $bcrypt = new BcryptSha('test');
    }

    public function testSetCost()
    {
        $this->bcrypt->setCost('16');
        $this->assertEquals('16', $this->bcrypt->getCost());
    }

    public function testSetWrongCost()
    {
        $this->setExpectedException('Laminas\Crypt\Password\Exception\InvalidArgumentException',
                                    'The cost parameter of bcrypt must be in range 04-31');
        $this->bcrypt->setCost('3');
    }

    public function testSetSalt()
    {
        $this->bcrypt->setSalt($this->salt);
        $this->assertEquals($this->salt, $this->bcrypt->getSalt());
    }

    public function testSetSmallSalt()
    {
        $this->setExpectedException('Laminas\Crypt\Password\Exception\InvalidArgumentException',
                                    'The length of the salt must be at least ' . Bcrypt::MIN_SALT_SIZE . ' bytes');
        $this->bcrypt->setSalt('small salt');
    }

    public function testCreateWithRandomSalt()
    {
        $password = $this->bcrypt->create('test');
        $this->assertNotEmpty($password);
        $this->assertEquals(60, strlen($password));
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

        $this->assertEquals('$2y$10$MTIzNDU2Nzg5MDEyMzQ1NetiAf47gp.MSGw.8x1/hESvXYfMep1em',
                                $this->bcrypt->create($password));
    }
}
