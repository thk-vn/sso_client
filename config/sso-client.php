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
    'revoke_uri'    => '/oauth/token/refresh',
    'menus_uri'     => '/api/menus',

    /*
    |--------------------------------------------------------------------------
    | Navigation Menu Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for navigation menu fetched from SSO server.
    |
    */
    'navigation_enabled' => env('SSO_NAVIGATION_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Save Token in Cache
    |--------------------------------------------------------------------------
    |
    | Configuration for saving SSO token in cache.
    |
    */
    'save_token_flg' => env('SSO_SAVE_TOKEN_FLG', true),
    'token_key' => env('SSO_TOKEN_KEY', 'sso_token'),
    'token_key_with_user_id' => env('SSO_TOKEN_KEY_WITH_USER_ID', false),

    /*
    |--------------------------------------------------------------------------
    | HTTP Client Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for HTTP client used to communicate with SSO server.
    |
    */
    'verify_ssl' => env('SSO_VERIFY_SSL', false),

    /*
    |--------------------------------------------------------------------------
    | User Model Configuration
    |--------------------------------------------------------------------------
    |
    | The User model class to use for createOrUpdateUser method.
    | If not set, will default to App\Models\User.
    |
    */
    'user_model' => env('SSO_USER_MODEL', 'App\\Models\\User'),

    /*
    |--------------------------------------------------------------------------
    | UI Configuration
    |--------------------------------------------------------------------------
    |
    | Views and routes used by the default controller.
    |
    */
    'login_view' => env('SSO_LOGIN_VIEW', 'auth.login'),
    'redirect_path' => env('SSO_REDIRECT_PATH', '/'),

    /*
    |--------------------------------------------------------------------------
    | Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Routes that should bypass the refresh navigation middleware.
    |
    */
    'middleware' => [
        'skip_routes' => [
            'login.show',
            'login',
            'sso.callback',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin Check Configuration
    |--------------------------------------------------------------------------
    |
    | Closure or string value to check if user is admin.
    | Example: function($user) { return $user->role === 'admin'; }
    | Or: 'admin' (will compare with user->role)
    |
    */
    'admin_check' => env('SSO_ADMIN_CHECK', null),
    'routes' => [
        'login' => env('SSO_LOGIN_ROUTE', 'login'),
        'login_show' => env('SSO_LOGIN_SHOW_ROUTE', 'login.show'),
        'dashboard_route' => env('SSO_DASHBOARD_ROUTE', 'dashboard'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Permission Middleware Configuration
    |--------------------------------------------------------------------------
    |
    | Route-permission mapping for PermissionMiddleware.
    | Override this in your app config or extend PermissionMiddleware class.
    |
    | Permissions are automatically loaded from SSO session (sso_permissions)
    | after successful authentication.
    |
    */
    'route_permissions' => [],

    /*
    |--------------------------------------------------------------------------
    | Remote Logout Configuration
    |--------------------------------------------------------------------------
    |
    | Secret token used to authenticate requests from SSO server for remote logout.
    | This should be a strong, random string shared between SSO server and client.
    | When SSO server needs to force logout a user (e.g., after permission changes),
    | it can call the remote-logout endpoint with this secret.
    |
    */
    'remote_logout_secret' => env('SSO_REMOTE_LOGOUT_SECRET', ''),
    'remote_logout_enabled' => env('SSO_REMOTE_LOGOUT_ENABLED', true),
];
