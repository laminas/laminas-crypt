<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Config\Config;
use Laminas\Crypt\Symmetric\Exception;
use Laminas\Crypt\Symmetric\Mcrypt;
use Laminas\Crypt\Symmetric\Padding\PKCS7;

/**
 * @group      Laminas_Crypt
 */
class McryptTest extends \PHPUnit_Framework_TestCase
{
    /** @var Mcrypt */
    protected $mcrypt;
    protected $key;
    protected $salt;
    protected $plaintext;

    public function setUp()
    {
        try {
            $this->mcrypt = new Mcrypt();
        } catch (Exception\RuntimeException $e) {
            $this->markTestSkipped('Mcrypt is not installed, I cannot execute the BlockCipherTest');
        }
        for ($i = 0; $i < 128; $i++) {
            $this->key .= chr(rand(0, 255));
            $this->salt .= chr(rand(0, 255));
        }
        $this->plaintext = file_get_contents(__DIR__ . '/../_files/plaintext');
    }

    public function testConstructByParams()
    {
        $options = array(
            'algorithm' => 'blowfish',
            'mode'      => 'cfb',
            'key'       => $this->key,
            'salt'      => $this->salt,
            'padding'   => 'pkcs7'
        );
        $mcrypt  = new Mcrypt($options);
        $this->assertTrue($mcrypt instanceof Mcrypt);
        $this->assertEquals($mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
        $this->assertEquals($mcrypt->getMode(), MCRYPT_MODE_CFB);
        $this->assertEquals($mcrypt->getKey(), substr($this->key, 0, $mcrypt->getKeySize()));
        $this->assertEquals($mcrypt->getSalt(), substr($this->salt, 0, $mcrypt->getSaltSize()));
        $this->assertTrue($mcrypt->getPadding() instanceof PKCS7);
    }

    public function testConstructByConfig()
    {
        $options = array(
            'algorithm' => 'blowfish',
            'mode'      => 'cfb',
            'key'       => $this->key,
            'salt'      => $this->salt,
            'padding'   => 'pkcs7'
        );
        $config  = new Config($options);
        $mcrypt  = new Mcrypt($config);
        $this->assertTrue($mcrypt instanceof Mcrypt);
        $this->assertEquals($mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
        $this->assertEquals($mcrypt->getMode(), MCRYPT_MODE_CFB);
        $this->assertEquals($mcrypt->getKey(), substr($this->key, 0, $mcrypt->getKeySize()));
        $this->assertEquals($mcrypt->getSalt(), substr($this->salt, 0, $mcrypt->getSaltSize()));
        $this->assertTrue($mcrypt->getPadding() instanceof PKCS7);
    }

    public function testConstructWrongParam()
    {
        $options = 'test';
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The options parameter must be an array, a Laminas\Config\Config object or a Traversable');
        $mcrypt = new Mcrypt($options);
    }

    public function testSetAlgorithm()
    {
        $this->mcrypt->setAlgorithm(MCRYPT_BLOWFISH);
        $this->assertEquals($this->mcrypt->getAlgorithm(), MCRYPT_BLOWFISH);
    }

    public function testSetWrongAlgorithm()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The algorithm test is not supported by Laminas\Crypt\Symmetric\Mcrypt');
        $this->mcrypt->setAlgorithm('test');
    }

    public function testSetKey()
    {
        $result = $this->mcrypt->setKey($this->key);
        $this->assertInstanceOf('Laminas\Crypt\Symmetric\Mcrypt', $result);
        $this->assertEquals($result, $this->mcrypt);
    }

    public function testSetEmptyKey()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The key cannot be empty');
        $result = $this->mcrypt->setKey('');
    }

    public function testSetShortKey()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException');
        $result = $this->mcrypt->setKey('short');
        $output = $this->mcrypt->encrypt('test');
    }

    public function testSetSalt()
    {
        $this->mcrypt->setSalt($this->salt);
        $this->assertEquals(substr($this->salt, 0, $this->mcrypt->getSaltSize()),
                            $this->mcrypt->getSalt());
        $this->assertEquals($this->salt, $this->mcrypt->getOriginalSalt());
    }

    /**
     * @expectedException Laminas\Crypt\Symmetric\Exception\InvalidArgumentException
     */
    public function testShortSalt()
    {
        $this->mcrypt->setSalt('short');
    }

    public function testSetMode()
    {
        $this->mcrypt->setMode(MCRYPT_MODE_CFB);
        $this->assertEquals(MCRYPT_MODE_CFB, $this->mcrypt->getMode());
    }

    public function testSetWrongMode()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The mode xxx is not supported by Laminas\Crypt\Symmetric\Mcrypt');
        $this->mcrypt->setMode('xxx');
    }

    public function testEncryptDecrypt()
    {
        $this->mcrypt->setKey($this->key);
        $this->mcrypt->setPadding(new PKCS7());
        $this->mcrypt->setSalt($this->salt);
        foreach ($this->mcrypt->getSupportedAlgorithms() as $algo) {
            foreach ($this->mcrypt->getSupportedModes() as $mode) {
                $this->mcrypt->setAlgorithm($algo);
                $this->mcrypt->setMode($mode);
                $encrypted = $this->mcrypt->encrypt($this->plaintext);
                $this->assertTrue(!empty($encrypted));
                $decrypted = $this->mcrypt->decrypt($encrypted);
                $this->assertTrue($decrypted !== false);
                $this->assertEquals($decrypted, $this->plaintext);
            }
        }
    }

    public function testEncryptWithoutKey()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException');
        $ciphertext = $this->mcrypt->encrypt('test');
    }

    public function testEncryptEmptyData()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The data to encrypt cannot be empty');
        $ciphertext = $this->mcrypt->encrypt('');
    }

    public function testEncryptWihoutSalt()
    {
        $this->mcrypt->setKey($this->key);
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The salt (IV) cannot be empty');
        $ciphertext = $this->mcrypt->encrypt($this->plaintext);
    }

    public function testDecryptEmptyData()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException',
                                    'The data to decrypt cannot be empty');
        $ciphertext = $this->mcrypt->decrypt('');
    }

    public function testDecryptWithoutKey()
    {
        $this->setExpectedException('Laminas\Crypt\Symmetric\Exception\InvalidArgumentException');
        $this->mcrypt->decrypt($this->plaintext);
    }
}
