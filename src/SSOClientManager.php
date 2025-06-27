<?php

namespace THKHD\SsoClient;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use THKHD\SsoClient\Exceptions\AccessTokenException;
use THKHD\SsoClient\Exceptions\UserFetchException;
use Session;

class SSOClientManager
{
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $authorizeUri;
    private string $tokenUri;
    private string $userUri;
    private string $serverUrl;
    private string $tokenKey;

    public function __construct()
    {
        $this->tokenKey     = config('sso-client.token_key') ?? 'sso_token';
        $this->clientId     = config('sso-client.client_id')     ?? throw new \RuntimeException('Missing SSO client_id');
        $this->clientSecret = config('sso-client.client_secret') ?? throw new \RuntimeException('Missing SSO client_secret');
        $this->redirectUri  = config('sso-client.redirect_uri')  ?? throw new \RuntimeException('Missing SSO redirect_uri');
        $this->authorizeUri = config('sso-client.authorize_uri') ?? throw new \RuntimeException('Missing SSO authorize_uri');
        $this->tokenUri     = config('sso-client.token_uri')     ?? throw new \RuntimeException('Missing SSO token_uri');
        $this->userUri      = config('sso-client.user_uri')      ?? throw new \RuntimeException('Missing SSO user_uri');
        $this->serverUrl    = config('sso-client.server_url')    ?? throw new \RuntimeException('Missing SSO server_url');
    }

    /**
     * Get access token from SSO server using authorization code.
     *
     * @param string $code The authorization code received from the SSO server.
     * @return array The access token data.
     * @throws AccessTokenException If the request fails or access token is not found.
     */
    public function getAccessToken(string $code): array
    {
        $url = $this->buildUrl($this->tokenUri);

        $response = Http::asForm()->post($url, [
            'grant_type'    => 'authorization_code',
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
            'code'          => $code,
        ]);

        if ($response->failed()) {
            Log::error('SSO token request failed', [
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);
            throw new AccessTokenException();
        }

        $data = $response->json() ?? [];

        if (empty($data['access_token'])) {
            Log::error('SSO access_token not found in response', ['data' => $data]);
            throw new AccessTokenException();
        }

        if (config('sso-client.save_token_flg', false)) {
            $this->saveSSOToken($data);
        }

        return $data;
    }

    /**
     * Build the authorization URL for SSO login.
     *
     * @param string $state The state parameter for CSRF protection.
     * @param array $extraParams Additional parameters to include in the query string.
     * @return string The complete authorization URL.
     */
    public function buildAuthorizationUrl(string $state, array $extraParams = []): string
    {
        $query = array_merge([
            'client_id'     => $this->clientId,
            'redirect_uri'  => $this->redirectUri,
            'response_type' => 'code',
            'scope'         => '',
            'state'         => $state,
        ], $extraParams);

        return $this->buildUrl($this->authorizeUri) . '?' . http_build_query($query);
    }

    /**
     * Build the full URL for a given endpoint.
     *
     * @param string $endpoint The endpoint to build the URL for.
     * @return string The complete URL.
     */
    private function buildUrl(string $endpoint): string
    {
        return rtrim($this->serverUrl, '/') . '/' . ltrim($endpoint, '/');
    }

    /**
     * Fetch user information from the SSO server using the access token.
     *
     * @param string $accessToken The access token to authenticate the request.
     * @return array The user information.
     * @throws UserFetchException If the request fails or user info is not found.
     */
    public function user(string $accessToken): array
    {
        $url = $this->buildUrl($this->userUri);

        $response = Http::withToken($accessToken)->get($url);

        if ($response->failed()) {
            Log::error('SSO user info fetch failed', [
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);
            throw new UserFetchException();
        }

        return $response->json();
    }

    /**
     * Save SSO token information in the session.
     *
     * @param array $tokenInfo The token information to save.
     */
    public function saveSSOToken(array $tokenInfo): void
    {
        Session::put($this->tokenKey, $tokenInfo);
    }

    /**
     * Get the SSO token from the session.
     *
     * @return array The SSO token information.
     */
    public function getSSOToken(): array
    {
        return Session::get($this->tokenKey, []);
    }
}
