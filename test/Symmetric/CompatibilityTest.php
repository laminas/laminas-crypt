<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric;

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
            [ 'des' ]
        ];
    }

    /**
     * @dataProvider getAlgos
     */
    public function testMcryptAndOpenssl($algo)
    {
        $key     = Rand::getBytes(56);
        $iv      = Rand::getBytes(16);
        $mcrypt  = new Mcrypt([
            'algo' => $algo,
            'key'  => $key,
            'iv'   => $iv
        ]);
        $openssl = new Openssl([
            'algo' => $algo,
            'key'  => $key,
            'iv'   => $iv
        ]);

        $plaintext = Rand::getBytes(1024);

        $encrypted = $mcrypt->encrypt($plaintext);
        $this->assertEquals($plaintext, $openssl->decrypt($encrypted));

        $encrypted = $openssl->encrypt($plaintext);
        $this->assertEquals($plaintext, $mcrypt->decrypt($encrypted));
    }
}
