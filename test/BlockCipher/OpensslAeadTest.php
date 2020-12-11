<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\BlockCipher;

use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Symmetric\Openssl;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

class OpensslAeadTest extends TestCase
{
    public function setUp(): void
    {
        $openssl = new Openssl();
        if (! $openssl->isAuthEncAvailable()) {
            $this->markTestSkipped('Authenticated encryption is not available on this platform');
        }
        $this->blockCipher = new BlockCipher($openssl);
    }

    public function getAuthEncryptionMode()
    {
        return [
            [ 'gcm' ],
            [ 'ccm' ]
        ];
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testEncryptDecrypt($mode)
    {
        $this->blockCipher->getCipher()->setMode($mode);
        $this->blockCipher->setKey('test');
        $plaintext = Rand::getBytes(1024);
        $ciphertext = $this->blockCipher->encrypt($plaintext);
        $this->assertEquals($plaintext, $this->blockCipher->decrypt($ciphertext));
    }
}
