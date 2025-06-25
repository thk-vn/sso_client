<?php

return [

    /*
    |--------------------------------------------------------------------------
    | SSO Server Endpoint
    |--------------------------------------------------------------------------
    |
    | Địa chỉ endpoint của hệ thống SSO Provider dùng để login, lấy user info,
    | refresh token, v.v...
    |
    */
    'server_url' => env('SSO_SERVER_URL', 'http://localhost:8000'),

    /*
    |--------------------------------------------------------------------------
    | OAuth2 Client Credentials
    |--------------------------------------------------------------------------
    |
    | Các thông tin định danh của client khi kết nối với SSO Provider.
    |
    */
    'client_id'     => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'redirect_uri'  => env('SSO_REDIRECT_URI', 'http://localhost:8000/sso-client/callback'),

    /*
    |--------------------------------------------------------------------------
    | Token Storage
    |--------------------------------------------------------------------------
    |
    | Lưu token ở đâu? 'session' hoặc 'cache' (dùng cache driver mặc định).
    |
    */
    'token_store' => 'session',

    /*
    |--------------------------------------------------------------------------
    | Route Prefix
    |--------------------------------------------------------------------------
    |
    | Prefix dùng cho các route do package này cung cấp, ví dụ: /sso/login
    |
    */
    'route_prefix' => 'sso-client',

    /*
    |--------------------------------------------------------------------------
    | Route Name
    |--------------------------------------------------------------------------
    |
    | Route name dẩn đến controller xử lí login
    | Cho phép từng app client tùy chỉnh route xử lý login (resolve()).
    |
    */
    'user_resolver' => 'sso-client.user-resolver',
];
