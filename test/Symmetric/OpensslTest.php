<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Openssl;

/**
 * @group      Laminas_Crypt
 */
class OpensslTest extends AbstractTest
{
    protected $adapterClass = Openssl::class;

    protected $default_algo = 'aes';

    protected $default_mode = 'cbc';

    protected $default_padding = 'pkcs7';

    public function testCtrMode()
    {
        if (! in_array('aes-256-ctr', openssl_get_cipher_methods())) {
            $this->markTestSkipped('The CTR mode is not supported');
        }
        $this->crypt->setAlgorithm('aes');
        $this->crypt->setMode('ctr');
        $this->assertEquals('ctr', $this->crypt->getMode());
    }
}
