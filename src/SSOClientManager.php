<?php

namespace THKHD\SsoClient;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\JsonResponse;

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
    public function fetchUserFromCode(string $code, string $redirectUri): ?array
    {
        $tokenResponse = Http::asForm()->get(config('sso-client.server_url') . '/api/oauth/token', [
            'grant_type'    => 'authorization_code',
            'client_id'     => config('sso-client.client_id'),
            'client_secret' => config('sso-client.client_secret'),
            'redirect_uri'  => $redirectUri,
            'code'          => $code,
        ]);

        if ($tokenResponse->failed()) {
            throw new \Exception('Failed to retrieve access token');
        }

        $accessToken = $tokenResponse->json()['access_token'];
        $userResponse = Http::withToken($accessToken)->get(config('sso-client.server_url') . '/api/user');

        if ($userResponse->failed()) {
            throw new \Exception('Failed to retrieve user');
        }

        return $userResponse->json();
    }
}
