<?php

namespace THKHD\SsoClient\Exceptions;

use Exception;

/**
 * Exception thrown when user details cannot be fetched.
 */
class UserFetchException extends Exception
{
    protected $message = 'Failed to retrieve user from SSO server.';
}