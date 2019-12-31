<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Password;

use Laminas\Crypt\Password\Apache;
use Laminas\Crypt\Password\Bcrypt;

/**
 * @group      Laminas_Crypt
 */
class ApacheTest extends \PHPUnit_Framework_TestCase
{
    /** @var Apache */
    public $apache;

    public function setUp()
    {
        $this->apache = new Apache();
    }

    public function testConstruct()
    {
        $this->apache = new Apache([
            'format' => 'crypt'
        ]);
        $this->assertInstanceOf('Laminas\Crypt\Password\Apache', $this->apache);
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\InvalidArgumentException
     */
    public function testWrongConstruct()
    {
        $this->apache = new Apache('crypt');
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\InvalidArgumentException
     */
    public function testWrongParamConstruct()
    {
        $this->apache = new Apache([
            'format' => 'crypto'
        ]);
    }

    public function testSetUserName()
    {
        $result = $this->apache->setUserName('test');
        $this->assertInstanceOf('Laminas\Crypt\Password\Apache', $result);
        $this->assertEquals('test', $this->apache->getUserName());
    }

    public function testSetFormat()
    {
        $result = $this->apache->setFormat('crypt');
        $this->assertInstanceOf('Laminas\Crypt\Password\Apache', $result);
        $this->assertEquals('crypt', $this->apache->getFormat());
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\InvalidArgumentException
     */
    public function testSetWrongFormat()
    {
        $result = $this->apache->setFormat('test');
    }

    public function testSetAuthName()
    {
        $result = $this->apache->setAuthName('test');
        $this->assertInstanceOf('Laminas\Crypt\Password\Apache', $result);
        $this->assertEquals('test', $this->apache->getAuthName());
    }

    public function testCrypt()
    {
        $this->apache->setFormat('crypt');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals(13, strlen($hash));
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testSha1()
    {
        $this->apache->setFormat('sha1');
        $hash = $this->apache->create('myPassword');
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testMd5()
    {
        $this->apache->setFormat('md5');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals('$apr1$', substr($hash, 0, 6));
        $this->assertEquals(37, strlen($hash));
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }

    public function testDigest()
    {
        $this->apache->setFormat('digest');
        $this->apache->setUserName('Enrico');
        $this->apache->setAuthName('Auth');
        $hash = $this->apache->create('myPassword');
        $this->assertEquals(32, strlen($hash));
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\RuntimeException
     */
    public function testDigestWithoutPreset()
    {
        $this->apache->setFormat('digest');
        $this->apache->create('myPassword');
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\RuntimeException
     */
    public function testDigestWithoutAuthName()
    {
        $this->apache->setFormat('digest');
        $this->apache->setUserName('Enrico');
        $this->apache->create('myPassword');
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\RuntimeException
     */
    public function testDigestWithoutUserName()
    {
        $this->apache->setFormat('digest');
        $this->apache->setAuthName('Auth');
        $this->apache->create('myPassword');
    }

    /**
     * Test vectors generated using openssl and htpasswd
     *
     * @see http://httpd.apache.org/docs/2.2/misc/password_encryptions.html
     */
    public static function provideTestVectors()
    {
        return [
            // openssl passwd -apr1 -salt z0Hhe5Lq myPassword
            ['myPassword', '$apr1$z0Hhe5Lq$6YdJKbkrJg77Dvw2gpuSA1'],
            // openssl passwd -crypt -salt z0Hhe5Lq myPassword
            ['myPassword', 'z0yXKQm465G4o'],
            // htpasswd -nbs myName myPassword
            ['myPassword', '{SHA}VBPuJHI7uixaa6LQGWx4s+5GKNE=']
        ];
    }

    /**
     * @dataProvider provideTestVectors
     */
    public function testVerify($password, $hash)
    {
        $this->assertTrue($this->apache->verify($password, $hash));
    }

    /**
     * @expectedException Laminas\Crypt\Password\Exception\InvalidArgumentException
     */
    public function testApr1Md5WrongSaltFormat()
    {
        $this->apache->verify('myPassword', '$apr1$z0Hhe5Lq3$6YdJKbkrJg77Dvw2gpuSA1');
        $this->apache->verify('myPassword', '$apr1$z0Hhe5L&$6YdJKbkrJg77Dvw2gpuSA1');
    }

    public function testCanVerifyBcryptHashes()
    {
        $bcrypt = new Bcrypt();
        $hash = $bcrypt->create('myPassword');
        $this->assertTrue($this->apache->verify('myPassword', $hash));
    }
}
