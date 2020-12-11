<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Password;

use Laminas\Crypt\Password\Bcrypt;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

/**
 * @group      Laminas_Crypt
 */
class BcryptBCTest extends TestCase
{
    public function setUp(): void
    {
        $this->bcrypt = new Bcrypt();
    }

    public function testBackwardCompatibilityV2()
    {
        $hash = $this->bcryptV2Implementation('test', 10);
        $this->assertTrue($this->bcrypt->verify('test', $hash));
    }

    /**
     * This is the Bcrypt::create implementation of Laminas 2.*
     *
     * @param string $Password
     * @param integer $cost
     * @param string $salt
     * @return string
     */
    protected function bcryptV2Implementation($password, $cost = 10, $salt = null)
    {
        if (empty($salt)) {
            $salt = Rand::getBytes(16);
        }

        $salt64 = mb_substr(str_replace('+', '.', base64_encode($salt)), 0, 22, '8bit');
        /**
         * Check for security flaw in the bcrypt implementation used by crypt()
         * @see http://php.net/security/crypt_blowfish.php
         */
        $prefix = '$2y$';
        $hash = crypt($password, $prefix . (string) $cost . '$' . $salt64);
        if (mb_strlen($hash, '8bit') < 13) {
            throw new RuntimeException('Error during the bcrypt generation');
        }
        return $hash;
    }
}
