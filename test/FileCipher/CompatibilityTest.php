<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\FileCipher;

use Laminas\Crypt\FileCipher;
use Laminas\Crypt\Symmetric\Mcrypt;
use Laminas\Crypt\Symmetric\Openssl;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

class CompatibilityTest extends TestCase
{
    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
        }
        if (! extension_loaded('mcrypt') || ! extension_loaded('openssl')) {
            $this->markTestSkipped(
                sprintf("I cannot execute %s without Mcrypt and OpenSSL installed", __CLASS__)
            );
        }
    }

    public function getAlgos()
    {
        return [
            [ 'aes' ],
            [ 'blowfish' ],
            [ 'des' ],
        ];
    }

    /**
     * @dataProvider getAlgos
     */
    public function testMcryptAndOpenssl($algo)
    {
        $fileCipherMcrypt  = new FileCipher(new Mcrypt);
        $fileCipherOpenssl = new FileCipher(new Openssl);

        $key = Rand::getBytes(16);
        $fileCipherMcrypt->setKey($key);
        $fileCipherOpenssl->setKey($key);

        $tmpIn   = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('laminas-crypt-test-in-');
        $tmpOut  = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('laminas-crypt-test-out-');
        $tmpOut2 = sys_get_temp_dir() . DIRECTORY_SEPARATOR . uniqid('laminas-crypt-test-out-');
        $plaintext = Rand::getBytes(1048576); // 1 Mb
        file_put_contents($tmpIn, $plaintext);

        $fileCipherMcrypt->encrypt($tmpIn, $tmpOut);
        $fileCipherOpenssl->decrypt($tmpOut, $tmpOut2);
        $this->assertEquals($plaintext, file_get_contents($tmpOut2));

        unlink($tmpOut2);
        unlink($tmpOut);

        $fileCipherOpenssl->encrypt($tmpIn, $tmpOut);
        $fileCipherMcrypt->decrypt($tmpOut, $tmpOut2);
        $this->assertEquals($plaintext, file_get_contents($tmpOut2));

        unlink($tmpIn);
        unlink($tmpOut);
        unlink($tmpOut2);
    }
}
