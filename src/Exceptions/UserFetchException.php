<?php

namespace THKHD\SsoClient\Exceptions;

use Exception;

class UserFetchException extends Exception
{
    protected $message = 'Failed to retrieve user from SSO server.';
}