<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Exception;
use Laminas\Crypt\Symmetric\Mcrypt;

/**
 * @group      Laminas_Crypt
 */
class McryptTest extends AbstractTest
{
    protected $adapterClass = Mcrypt::class;

    protected $default_algo = 'blowfish';

    protected $default_mode = 'cfb';

    protected $default_padding = 'pkcs7';

    public function setUp(): void
    {
        if (PHP_VERSION_ID >= 70100) {
            $this->markTestSkipped('The Mcrypt tests are deprecated for PHP 7.1+');
        }
        parent::setUp();
    }

    public function testSetShortKey()
    {
        foreach ($this->crypt->getSupportedAlgorithms() as $algo) {
            $this->crypt->setAlgorithm($algo);
            try {
                $result = $this->crypt->setKey('four');
            } catch (\Exception $ex) {
                $result = $ex;
            }
            if ($algo != 'blowfish') {
                $this->assertInstanceOf(
                    Exception\InvalidArgumentException::class,
                    $result
                );
            } else {
                $this->assertInstanceOf($this->adapterClass, $result);
            }
        }
    }
}
