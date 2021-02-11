<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Key\Derivation;

use function array_keys;
use function in_array;
use function mb_strlen;
use function mhash_keygen_s2k;

/**
 * Salted S2K key generation (OpenPGP document, RFC 2440)
 */
class SaltedS2k
{
    protected static $supportedMhashAlgos = [
        'adler32'    => MHASH_ADLER32,
        'md2'        => MHASH_MD2,
        'md4'        => MHASH_MD4,
        'md5'        => MHASH_MD5,
        'sha1'       => MHASH_SHA1,
        'sha224'     => MHASH_SHA224,
        'sha256'     => MHASH_SHA256,
        'sha384'     => MHASH_SHA384,
        'sha512'     => MHASH_SHA512,
        'ripemd128'  => MHASH_RIPEMD128,
        'ripemd256'  => MHASH_RIPEMD256,
        'ripemd320'  => MHASH_RIPEMD320,
        'haval128'   => MHASH_HAVAL128,
        'haval160'   => MHASH_HAVAL160,
        'haval192'   => MHASH_HAVAL192,
        'haval224'   => MHASH_HAVAL224,
        'haval256'   => MHASH_HAVAL256,
        'tiger'      => MHASH_TIGER,
        'tiger128'   => MHASH_TIGER128,
        'tiger160'   => MHASH_TIGER160,
        'whirpool'   => MHASH_WHIRLPOOL,
        'snefru256'  => MHASH_SNEFRU256,
        'gost'       => MHASH_GOST,
        'crc32'      => MHASH_CRC32,
        'crc32b'     => MHASH_CRC32B
    ];

    /**
     * Generate the new key
     *
     * @param  string  $hash       The hash algorithm to be used by HMAC
     * @param  string  $password   The source password/key
     * @param  int $bytes      The output size in bytes
     * @param  string  $salt       The salt of the algorithm
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public static function calc($hash, $password, $salt, $bytes)
    {
        if (! in_array($hash, array_keys(static::$supportedMhashAlgos))) {
            throw new Exception\InvalidArgumentException("The hash algorithm $hash is not supported by " . __CLASS__);
        }
        if (mb_strlen($salt, '8bit') < 8) {
            throw new Exception\InvalidArgumentException('The salt size must be at least of 8 bytes');
        }
        return mhash_keygen_s2k(static::$supportedMhashAlgos[$hash], $password, $salt, $bytes);
    }
}
