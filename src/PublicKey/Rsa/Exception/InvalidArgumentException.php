<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\PublicKey\Rsa\Exception;

use Laminas\Crypt\Exception;

/**
 * Invalid argument exception
 *
 * @category   Laminas
 * @package    Laminas_Crypt
 * @subpackage PublicKey
 */
class InvalidArgumentException
    extends Exception\InvalidArgumentException
    implements ExceptionInterface
{}
