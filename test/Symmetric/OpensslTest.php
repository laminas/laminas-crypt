<?php

namespace LaminasTest\Crypt\Symmetric;

use Laminas\Crypt\Symmetric\Openssl;

use function in_array;
use function openssl_get_cipher_methods;

/**
 * @group      Laminas_Crypt
 */
class OpensslTest extends AbstractTestCase
{
    /** @var string */
    protected $adapterClass = Openssl::class;

    /** @var string */
    protected $defaultAlgo = 'aes';

    /** @var string */
    protected $defaultMode = 'cbc';

    /** @var string */
    protected $defaultPadding = 'pkcs7';

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
