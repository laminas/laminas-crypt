<?php

namespace LaminasTest\Crypt\Symmetric;

use Exception;
use Laminas\Crypt\Symmetric\Mcrypt;
use PHPUnit\Framework\TestCase;

use function restore_error_handler;
use function set_error_handler;

use const E_ALL;
use const PHP_VERSION_ID;

class McryptDeprecatedTest extends TestCase
{
    public function setUp(): void
    {
        if (PHP_VERSION_ID < 70100) {
            $this->markTestSkipped('The Mcrypt deprecated test is for PHP 7.1+');
        }
    }

    public function testDeprecated()
    {
        set_error_handler(
            static function ($errno, $errstr) {
                restore_error_handler();
                throw new Exception($errstr, $errno);
            },
            E_ALL
        );
        $this->expectExceptionMessage(
            'The Mcrypt extension is deprecated from PHP 7.1+. We suggest to use Laminas\Crypt\Symmetric\Openssl.'
        );
        new Mcrypt();
    }
}
