<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt;

use Laminas\Crypt\Utils;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

/**
 * @group      Laminas_Crypt
 */
class UtilsTest extends \PHPUnit_Framework_TestCase
{
    public function testCompareStringsBasic()
    {
        $this->assertTrue(Utils::compareStrings('test', 'test'));
        $this->assertFalse(Utils::compareStrings('test', 'Test'));
    }
}
