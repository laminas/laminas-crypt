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
}
