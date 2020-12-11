<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\BlockCipher;

use Laminas\Crypt\BlockCipher;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

class CompatibilityTest extends TestCase
{
    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
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
        try {
            $blockCipherMcrypt  = BlockCipher::factory('mcrypt', [ 'algo' => $algo ]);
            $blockCipherOpenssl = BlockCipher::factory('openssl', [ 'algo' => $algo ]);
        } catch (\Exception $e) {
            $this->markTestSkipped($e->getMessage());
        }

        $key       = Rand::getBytes(32);
        $plaintext = Rand::getBytes(1024);
        $blockCipherMcrypt->setKey($key);
        $blockCipherOpenssl->setKey($key);

        $encrypted = $blockCipherMcrypt->encrypt($plaintext);
        $this->assertEquals($plaintext, $blockCipherOpenssl->decrypt($encrypted));

        $encrypted = $blockCipherOpenssl->encrypt($plaintext);
        $this->assertEquals($plaintext, $blockCipherMcrypt->decrypt($encrypted));
    }
}
