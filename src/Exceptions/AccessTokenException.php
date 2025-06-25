<?php

namespace THKHD\SsoClient\Exceptions;

use Exception;

class AccessTokenException extends Exception
{
    protected $message = 'Failed to retrieve access token.';
}