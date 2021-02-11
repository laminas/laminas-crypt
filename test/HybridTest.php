<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt;

use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Exception;
use Laminas\Crypt\Hybrid;
use Laminas\Crypt\PublicKey\Rsa;
use Laminas\Crypt\PublicKey\RsaOptions;
use PHPUnit\Framework\TestCase;

class HybridTest extends TestCase
{
    protected $hybrid;

    public function setUp(): void
    {
        if (! extension_loaded('openssl')) {
            $this->markTestSkipped('The OpenSSL extension is required');
        }
        $this->hybrid = new Hybrid();
    }

    public function testConstructor()
    {
        $hybrid = new Hybrid();
        $this->assertInstanceOf(Hybrid::class, $hybrid);
    }

    public function testConstructorWithParameters()
    {
        $hybrid = new Hybrid(
            $this->createMock(BlockCipher::class),
            $this->createMock(Rsa::class),
        );
        $this->assertInstanceOf(Hybrid::class, $hybrid);
    }

    public function testGetDefaultBlockCipherInstance()
    {
        $bCipher = $this->hybrid->getBlockCipherInstance();
        $this->assertInstanceOf(BlockCipher::class, $bCipher);
    }

    public function testGetDefaultRsaInstance()
    {
        $rsa = $this->hybrid->getRsaInstance();
        $this->assertInstanceOf(Rsa::class, $rsa);
    }

    public function testEncryptDecryptWithOneStringKey()
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey()->toString();
        $privateKey = $rsaOptions->getPrivateKey()->toString();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptDecryptWithOneStringKeyAndPassphrase()
    {
        $passPhrase = 'test';
        $rsaOptions = new RsaOptions([
            'pass_phrase' => $passPhrase
        ]);
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey()->toString();
        $privateKey = $rsaOptions->getPrivateKey()->toString();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey, $passPhrase);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleStringKeys()
    {
        $publicKeys  = [];
        $privateKeys = [];
        $rsaOptions  = new RsaOptions();

        for ($id = 0; $id < 5; $id++) {
            $rsaOptions->generateKeys([
                'private_key_bits' => 1024,
            ]);
            $publicKeys[$id]  = $rsaOptions->getPublicKey()->toString();
            $privateKeys[$id] = $rsaOptions->getPrivateKey()->toString();
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], null, $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    public function testEncryptDecryptWithOneObjectKey()
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey();
        $privateKey = $rsaOptions->getPrivateKey();

        $encrypted = $this->hybrid->encrypt('test', $publicKey);
        $plaintext = $this->hybrid->decrypt($encrypted, $privateKey);
        $this->assertEquals('test', $plaintext);
    }

    public function testEncryptWithMultipleObjectKeys()
    {
        $publicKeys  = [];
        $privateKeys = [];
        $rsaOptions  = new RsaOptions();

        for ($id = 0; $id < 5; $id++) {
            $rsaOptions->generateKeys([
                'private_key_bits' => 1024,
            ]);
            $publicKeys[$id]  = $rsaOptions->getPublicKey();
            $privateKeys[$id] = $rsaOptions->getPrivateKey();
        }

        $encrypted = $this->hybrid->encrypt('test', $publicKeys);
        for ($id = 0; $id < 5; $id++) {
            $plaintext = $this->hybrid->decrypt($encrypted, $privateKeys[$id], null, $id);
            $this->assertEquals('test', $plaintext);
        }
    }

    public function testFailToDecryptWithOneKey()
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $publicKey  = $rsaOptions->getPublicKey();
        // Generate a new private key
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $privateKey = $rsaOptions->getPrivateKey();

        // encrypt using a single key
        $encrypted = $this->hybrid->encrypt('test', $publicKey);

        $this->expectException(Exception\RuntimeException::class);
        // try to decrypt using a different private key throws an exception
        $this->hybrid->decrypt($encrypted, $privateKey);
    }

    public function testFailToEncryptUsingPrivateKey()
    {
        $rsaOptions = new RsaOptions();
        $rsaOptions->generateKeys([
            'private_key_bits' => 1024,
        ]);
        $privateKey = $rsaOptions->getPrivateKey();

        $this->expectException(Exception\RuntimeException::class);
        // encrypt using a PrivateKey object throws an exception
        $this->hybrid->encrypt('test', $privateKey);
    }
}
