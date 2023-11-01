<?php

namespace LaminasTest\Crypt\FileCipher;

use Laminas\Crypt\FileCipher;
use Laminas\Crypt\Symmetric;
use Laminas\Crypt\Symmetric\Openssl;
use Laminas\Crypt\Symmetric\SymmetricInterface;

class OpensslTest extends AbstractFileCipher
{
    public function setUp(): void
    {
        try {
            $this->fileCipher = new FileCipher(new Openssl());
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testDefaultCipher()
    {
        $fileCipher = new FileCipher();
        $this->assertInstanceOf(Openssl::class, $fileCipher->getCipher());
    }

    /**
     * @requires PHP <= 8.2
     */
    public function testSetCipher()
    {
        $cipher = new Openssl([
            'algo' => 'blowfish',
        ]);
        $this->fileCipher->setCipher($cipher);
        $this->assertInstanceOf(SymmetricInterface::class, $this->fileCipher->getCipher());
        $this->assertEquals($cipher, $this->fileCipher->getCipher());
    }
}
