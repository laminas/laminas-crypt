<?php

/**
 * @see       https://github.com/laminas/laminas-crypt for the canonical source repository
 * @copyright https://github.com/laminas/laminas-crypt/blob/master/COPYRIGHT.md
 * @license   https://github.com/laminas/laminas-crypt/blob/master/LICENSE.md New BSD License
 */

if (class_exists(\PHPUnit_Framework_Error::class)) {
    class_alias(\PHPUnit_Framework_Error::class, \PHPUnit\Framework\Error\Error::class);
}

if (class_exists(\PHPUnit_Framework_Error_Deprecated::class)) {
    class_alias(\PHPUnit_Framework_Error_Deprecated::class, \PHPUnit\Framework\Error\Deprecated::class);
}
