<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt;

use Laminas\Crypt\Hash;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

/**
 * @group      Laminas_Crypt
 */
class HashTest extends TestCase
{
    public function testIsSupportedAndCache()
    {
        $reflectionClass = new ReflectionClass(Hash::class);
        $lastAlgorithmSupportedProperty = $reflectionClass->getProperty('lastAlgorithmSupported');
        $lastAlgorithmSupportedProperty->setAccessible(true);

        Hash::clearLastAlgorithmCache();
        $this->assertEquals(null, $lastAlgorithmSupportedProperty->getValue());

        $algorithm = 'sha512';

        // cache value must be exactly equal to the original input
        $this->assertTrue(Hash::isSupported($algorithm));
        $this->assertEquals($algorithm, $lastAlgorithmSupportedProperty->getValue());
        $this->assertNotEquals('sHa512', $lastAlgorithmSupportedProperty->getValue());

        // cache value must be exactly equal to the first input (cache hit)
        Hash::isSupported('sha512');
        $this->assertEquals($algorithm, $lastAlgorithmSupportedProperty->getValue());

        // cache changes with a new algorithm
        $this->assertTrue(Hash::isSupported('sha1'));
        $this->assertEquals('sha1', $lastAlgorithmSupportedProperty->getValue());

        // cache don't change due wrong algorithm
        $this->assertFalse(Hash::isSupported('wrong'));
        $this->assertEquals('sha1', $lastAlgorithmSupportedProperty->getValue());

        Hash::clearLastAlgorithmCache();
        $this->assertEquals(null, $lastAlgorithmSupportedProperty->getValue());
    }

    // SHA1 tests taken from RFC 3174
    public function provideSha1Data()
    {
        return [
            ['abc',
                  strtolower('A9993E364706816ABA3E25717850C26C9CD0D89D')],
            ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
                  strtolower('84983E441C3BD26EBAAE4AA1F95129E5E54670F1')],
            [str_repeat('a', 1000000),
                  strtolower('34AA973CD4C4DAA4F61EEB2BDBAD27316534016F')],
            [str_repeat('01234567', 80),
                  strtolower('DEA356A2CDDD90C7A7ECEDC5EBB563934F460452')]
        ];
    }

    /**
     * @dataProvider provideSha1Data
     */
    public function testSha1($data, $output)
    {
        $hash = Hash::compute('sha1', $data);
        $this->assertEquals($output, $hash);
    }

    // SHA-224 tests taken from RFC 3874
    public function provideSha224Data()
    {
        return [
            ['abc', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'],
            ['abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
                  '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'],
            [str_repeat('a', 1000000),
                  '20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67']
        ];
    }

    /**
     * @dataProvider provideSha224Data
     */
    public function testSha224($data, $output)
    {
        $hash = Hash::compute('sha224', $data);
        $this->assertEquals($output, $hash);
    }

    // MD5 test suite taken from RFC 1321
    public function provideMd5Data()
    {
        return [
            ['', 'd41d8cd98f00b204e9800998ecf8427e'],
            ['a', '0cc175b9c0f1b6a831c399e269772661'],
            ['abc', '900150983cd24fb0d6963f7d28e17f72'],
            ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
            ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
            ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                  'd174ab98d277d9f5a5611c2c9f419d9f'],
            [str_repeat('1234567890', 8), '57edf4a22be3c955ac49da2e2107b67a']
        ];
    }

    /**
     * @dataProvider provideMd5Data
     */
    public function testMd5($data, $output)
    {
        $hash = Hash::compute('md5', $data);
        $this->assertEquals($output, $hash);
    }

    public function testNullHashAlgorithm()
    {
        Hash::clearLastAlgorithmCache();
        $this->expectException('Laminas\Crypt\Exception\InvalidArgumentException');
        $this->expectExceptionMessage('Hash algorithm provided is not supported on this PHP installation');
        Hash::compute(null, 'test');
    }

    public function testWrongHashAlgorithm()
    {
        $this->expectException('Laminas\Crypt\Exception\InvalidArgumentException');
        $this->expectExceptionMessage('Hash algorithm provided is not supported on this PHP installation');
        Hash::compute('wrong', 'test');
    }

    public function testBinaryOutput()
    {
        $hash = Hash::compute('sha1', 'test', Hash::OUTPUT_BINARY);
        $this->assertEquals('qUqP5cyxm6YcTAhz05Hph5gvu9M=', base64_encode($hash));
    }
}
