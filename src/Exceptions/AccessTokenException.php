<?php

namespace THKHD\SsoClient\Exceptions;

use Exception;

/**
 * Exception thrown when an access token cannot be retrieved.
 */
class AccessTokenException extends Exception
{
    protected $message = 'Failed to retrieve access token.';
}