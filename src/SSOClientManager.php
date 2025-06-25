<?php

namespace THKHD\SsoClient;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\JsonResponse;
use THKHD\SsoClient\Exceptions\AccessTokenException;
use THKHD\SsoClient\Exceptions\UserFetchException;
use Illuminate\Support\Facades\Session;

class SSOClientManager
{
    /**
     * Fetch User From Code
     * 
     * @param string $code
     * @param string $redirectUri
     * @throws \Exception
     * 
     * @return JsonResponse
     */
    public function fetchUserFromCode(string $code, string $redirectUri)
    {
        try {
            $tokenResponse = Http::asForm()->get(config('sso-client.server_url') . '/api/oauth/token', [
                'grant_type'    => 'authorization_code',
                'client_id'     => config('sso-client.client_id'),
                'client_secret' => config('sso-client.client_secret'),
                'redirect_uri'  => $redirectUri,
                'code'          => $code,
            ]);

            if ($tokenResponse->failed()) {
                throw new AccessTokenException();
            }

            $accessToken = $tokenResponse->json()['access_token'];
            $userResponse = Http::withToken($accessToken)->get(config('sso-client.server_url') . '/api/user');

            if ($userResponse->failed()) {
                throw new UserFetchException();
            }

            Session::put('sso_user', $userResponse->json());

            return $userResponse->json();
        } catch (\Throwable $e) {
            report($e);
            throw $e;
        }
    }

    /**
     * Get SSO User
     * 
     * @return array
     */
    public function user()
    {
        return Session::get('sso_user', null);
    }
}
