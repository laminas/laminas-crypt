<?php

namespace Laminas\Crypt\Exception;

use Interop\Container\Exception\NotFoundException as InteropNotFoundException;

/**
 * Runtime argument exception
 */
class NotFoundException extends \DomainException implements InteropNotFoundException
{
}
