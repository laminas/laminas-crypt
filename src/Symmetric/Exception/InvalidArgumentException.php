<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Symmetric\Exception;

use Laminas\Crypt\Exception;

/**
 * Invalid argument exception
 *
 * @category   Laminas
 * @package    Laminas_Crypt
 * @subpackage Exception
 */
class InvalidArgumentException extends Exception\InvalidArgumentException implements
    ExceptionInterface
{}
