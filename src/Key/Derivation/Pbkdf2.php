<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Key\Derivation;

use Laminas\Crypt\Hmac;

/**
 * PKCS #5 v2.0 standard RFC 2898
 *
 * @category   Laminas
 * @package    Laminas_Crypt
 */
class Pbkdf2
{
    /**
     * Generate the new key
     *
     * @param  string  $hash       The hash algorithm to be used by HMAC
     * @param  string  $password   The source password/key
     * @param  string  $salt
     * @param  integer $iterations The number of iterations
     * @param  integer $length     The output size
     * @throws Exception\InvalidArgumentException
     * @return string
     */
    public static function calc($hash, $password, $salt, $iterations, $length)
    {
        if (!in_array($hash, Hmac::getSupportedAlgorithms())) {
            throw new Exception\InvalidArgumentException("The hash algorihtm $hash is not supported by " . __CLASS__);
        }
        $num    = ceil($length / Hmac::getOutputSize($hash, Hmac::OUTPUT_BINARY));
        $result = '';
        for ($block = 1; $block <= $num; $block++) {
            $hmac = Hmac::compute($password, $hash, $salt . pack('N', $block), Hmac::OUTPUT_BINARY);
            $mix  = $hmac;
            for ($i = 1; $i < $iterations; $i++) {
                $hmac = Hmac::compute($password, $hash, $hmac, Hmac::OUTPUT_BINARY);
                $mix ^= $hmac;
            }
            $result .= $mix;
        }
        return substr($result, 0, $length);
    }
}
