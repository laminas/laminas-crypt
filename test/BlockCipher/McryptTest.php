<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\BlockCipher;

use Laminas\Crypt\BlockCipher;
use Laminas\Crypt\Symmetric;

class MCryptTest extends AbstractBlockCipherTest
{
    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
        }
        try {
            $this->cipher = new Symmetric\Mcrypt([
                'algorithm' => 'aes',
                'mode'      => 'cbc',
                'padding'   => 'pkcs7'
            ]);
        } catch (Symmetric\Exception\RuntimeException $e) {
            $this->markTestSkipped($e->getMessage());
        }
        parent::setUp();
    }

    public function testSetCipher()
    {
        $mcrypt = new Symmetric\Mcrypt();
        $result = $this->blockCipher->setCipher($this->cipher);
        $this->assertEquals($result, $this->blockCipher);
        $this->assertEquals($this->cipher, $this->blockCipher->getCipher());
    }

    public function testFactory()
    {
        $this->blockCipher = BlockCipher::factory('mcrypt', ['algo' => 'blowfish']);
        $this->assertInstanceOf(Symmetric\Mcrypt::class, $this->blockCipher->getCipher());
        $this->assertEquals('blowfish', $this->blockCipher->getCipher()->getAlgorithm());
    }

    public function testFactoryEmptyOptions()
    {
        $this->blockCipher = BlockCipher::factory('mcrypt');
        $this->assertInstanceOf(Symmetric\Mcrypt::class, $this->blockCipher->getCipher());
    }
}
