<?php

namespace LaminasTest\Crypt\Password;

use Laminas\Crypt\Password\Bcrypt;
use Laminas\Math\Rand;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function crypt;
use function mb_strlen;
use function mb_substr;
use function str_replace;

/**
 * @group      Laminas_Crypt
 */
class BcryptBCTest extends TestCase
{
    private Bcrypt $bcrypt;

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
     */
    protected function bcryptV2Implementation(string $password, int $cost = 10, ?string $salt = null): string
    {
        if (empty($salt)) {
            $salt = Rand::getBytes(16);
        }

        $salt64 = mb_substr(str_replace('+', '.', base64_encode($salt)), 0, 22, '8bit');
        /**
         * Check for security flaw in the bcrypt implementation used by crypt()
         *
         * @see http://php.net/security/crypt_blowfish.php
         */
        $prefix = '$2y$';
        $hash   = crypt($password, $prefix . (string) $cost . '$' . $salt64);
        if (mb_strlen($hash, '8bit') < 13) {
            throw new RuntimeException('Error during the bcrypt generation');
        }
        return $hash;
    }
}
