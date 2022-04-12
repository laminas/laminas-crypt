<?php

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

    /** @psalm-return array<array-key, array{0: string}> */
    public function getAuthEncryptionMode(): array
    {
        return [
            ['gcm'],
            ['ccm'],
        ];
    }

    /**
     * @dataProvider getAuthEncryptionMode
     */
    public function testEncryptDecrypt(string $mode)
    {
        $this->blockCipher->getCipher()->setMode($mode);
        $this->blockCipher->setKey('test');
        $plaintext  = Rand::getBytes(1024);
        $ciphertext = $this->blockCipher->encrypt($plaintext);
        $this->assertEquals($plaintext, $this->blockCipher->decrypt($ciphertext));
    }
}
