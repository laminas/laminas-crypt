<?php

namespace LaminasTest\Crypt;

use Laminas\Crypt\Utils;
use PHPUnit\Framework\TestCase;

/**
 * Outside the Internal Function tests, tests do not distinguish between hash and mhash
 * when available. All tests use Hashing algorithms both extensions implement.
 */

/**
 * @group      Laminas_Crypt
 */
class UtilsTest extends TestCase
{
    public function testCompareStringsBasic()
    {
        $this->assertTrue(Utils::compareStrings('test', 'test'));
        $this->assertFalse(Utils::compareStrings('test', 'Test'));
    }
}
