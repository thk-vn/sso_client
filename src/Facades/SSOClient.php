<?php

namespace THKHD\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;

class SSOClient extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'sso-client';
    }
}
