<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Mcrypt;

class MCryptDeprecatedTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        if (PHP_VERSION_ID < 70100) {
            $this->markTestSkipped('The Mcrypt deprecated test is for PHP 7.1+');
        }
    }

    /**
     * @expectedException PHPUnit_Framework_Error_Deprecated
     */
    public function testDeprecated()
    {
        $mcrypt = new Mcrypt();
    }
}
