<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

namespace Laminas\Crypt\Exception;

use Psr\Container\NotFoundExceptionInterface;

/**
 * Runtime argument exception
 */
class NotFoundException extends \DomainException implements NotFoundExceptionInterface
{
}
