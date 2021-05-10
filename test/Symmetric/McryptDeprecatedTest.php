<?php

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Mcrypt;
use PHPUnit\Framework\TestCase;

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
        $this->expectDeprecation();
        new Mcrypt();
    }
}
