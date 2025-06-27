<?php

return [

    /*
    |--------------------------------------------------------------------------
    | SSO Server Endpoint
    |--------------------------------------------------------------------------
    |
    | The endpoint address of the SSO Provider system used to login and get user info.
    | refresh token, v.v...
    |
    */
    'server_url' => env('SSO_SERVER_URL', 'http://localhost:8000'),

    /*
    |--------------------------------------------------------------------------
    | OAuth2 Client Credentials
    |--------------------------------------------------------------------------
    |
    | Client identification information when connecting to SSO Provider.
    |
    */
    'client_id'     => env('SSO_CLIENT_ID', ''),
    'client_secret' => env('SSO_CLIENT_SECRET', ''),
    'redirect_uri'  => env('SSO_REDIRECT_URI', 'http://localhost:8001/sso-client/callback'),
    'token_uri'     => '/oauth/token',
    'authorize_uri' => '/oauth/authorize',
    'user_uri'      => '/api/user',

    /*
    |--------------------------------------------------------------------------
    | Save Token in Session
    |--------------------------------------------------------------------------
    */
    'save_token_flg' => true,
    'token_key' => 'sso_token',
];
