<?php

namespace THKHD\SsoClient;

use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use THKHD\SsoClient\Exceptions\AccessTokenException;
use THKHD\SsoClient\Exceptions\UserFetchException;

class SSOClientManager
{
    private const NAVIGATION_CACHE_KEY = 'navigation_html';

    private PendingRequest $httpClient;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $authorizeUri;
    private string $tokenUri;
    private string $userUri;
    private string $serverUrl;
    private string $tokenKey;
    private ?string $menusUri;
    private ?string $revokeUri;

    /**
     * Create a new SSO client manager instance.
     */
    public function __construct()
    {
        $this->tokenKey = config('sso-client.token_key', 'sso_token');
        $this->clientId = config('sso-client.client_id') ?? throw new \RuntimeException('Missing SSO client_id');
        $this->clientSecret = config('sso-client.client_secret') ?? throw new \RuntimeException('Missing SSO client_secret');
        $this->redirectUri = config('sso-client.redirect_uri') ?? throw new \RuntimeException('Missing SSO redirect_uri');
        $this->authorizeUri = config('sso-client.authorize_uri') ?? throw new \RuntimeException('Missing SSO authorize_uri');
        $this->tokenUri = config('sso-client.token_uri') ?? throw new \RuntimeException('Missing SSO token_uri');
        $this->userUri = config('sso-client.user_uri') ?? throw new \RuntimeException('Missing SSO user_uri');
        $this->serverUrl = config('sso-client.server_url') ?? throw new \RuntimeException('Missing SSO server_url');
        $this->menusUri = config('sso-client.menus_uri');
        $this->revokeUri = config('sso-client.revoke_uri');
        $this->httpClient = $this->createHttpClient();
    }

    /**
     * Get the access token from the SSO server.
     *
     * @param string $code
     * @return array
     * @throws \THKHD\SsoClient\Exceptions\AccessTokenException
     */
    public function getAccessToken(string $code): array
    {
        $response = $this->httpClient->asForm()->post($this->buildUrl($this->tokenUri), [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
        ]);

        if ($response->failed()) {
            Log::error('SSO token request failed', ['status' => $response->status(), 'body' => $response->body()]);
            throw new AccessTokenException();
        }

        $data = $response->json() ?? [];

        if (empty($data['access_token'])) {
            Log::error('SSO access_token not found in response', ['data' => $data]);
            throw new AccessTokenException();
        }

        if (config('sso-client.save_token_flg', true)) {
            $this->saveSSOToken($data['access_token']);
        }

        return $data;
    }

    /**
     * Build the authorization URL.
     *
     * @param string $state
     * @param array $extraParams
     * @return string
     */
    public function buildAuthorizationUrl(string $state, array $extraParams = []): string
    {
        $query = array_merge([
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => '',
            'state' => $state,
        ], $extraParams);

        return $this->buildUrl($this->authorizeUri) . '?' . http_build_query($query);
    }

    /**
     * Get the user information from the SSO server (Alias for getUser).
     *
     * @param string $accessToken
     * @return array
     */
    public function user(string $accessToken): array
    {
        return $this->getUser($accessToken);
    }

    /**
     * Get the user information from the SSO server.
     *
     * @param string $accessToken
     * @return array
     * @throws \THKHD\SsoClient\Exceptions\UserFetchException
     */
    public function getUser(string $accessToken): array
    {
        $response = $this->httpClient->withToken($accessToken)->get($this->buildUrl($this->userUri));

        if ($response->failed()) {
            Log::error('Failed to fetch user info from SSO', [
                'status' => $response->status(),
                'body' => $response->body(),
                'endpoint' => $this->buildUrl($this->userUri),
            ]);
            throw new UserFetchException();
        }

        $data = $response->json();

        return $data['data'] ?? $data;
    }

    /**
     * Store the navigation menu in the session.
     *
     * @param string $accessToken
     * @param string|null $lang
     * @return void
     * @throws \Exception
     */
    public function storeNavigationMenu(string $accessToken, ?string $lang = 'en'): void
    {
        if (!$this->menusUri) {
            throw new \RuntimeException('menus_uri is not configured');
        }

        $response = $this->httpClient->withToken($accessToken)->get($this->buildUrl($this->menusUri), [
            'lang' => $lang,
            'client_url' => config('app.url'),
        ]);

        if ($response->successful()) {
            $this->saveNavigation($response->body());
            return;
        }

        $this->clearSSOToken();

        if ($response->status() === 403) {
            throw new \Exception($response->json()['message'] ?? 'Page cannot be accessed.');
        }

        throw new \Exception('Unauthenticated.');
    }

    /**
     * Get the navigation menu from the session.
     *
     * @return mixed
     */
    public function getNavigationMenu(): mixed
    {
        return session(self::NAVIGATION_CACHE_KEY);
    }

    /**
     * Clear the navigation menu from the session.
     *
     * @return void
     */
    public function clearNavigationMenu(): void
    {
        session()->forget(self::NAVIGATION_CACHE_KEY);
    }

    /**
     * Validate the state parameter.
     *
     * @param string|null $sessionState
     * @param string|null $requestState
     * @return bool
     */
    public function validateState(?string $sessionState, ?string $requestState): bool
    {
        return $sessionState && $requestState && hash_equals($sessionState, $requestState);
    }

    /**
     * Create or update the user in the local database.
     *
     * @param array $userData
     * @param callable|null $callback
     * @return mixed
     * @throws \Exception
     */
    public function createOrUpdateUser(array $userData, ?callable $callback = null): mixed
    {
        if (!isset($userData['email'])) {
            throw new \Exception('Email not found in user information.');
        }

        try {
            $user = $callback ? $callback($userData) : $this->createOrUpdateUserDefault($userData);

            Log::info('User synchronized from SSO', ['user_id' => $user->id ?? null, 'email' => $userData['email']]);

            return $user;
        } catch (\Exception $e) {
            Log::error('Failed to create or update user from SSO', ['email' => $userData['email'] ?? null, 'error' => $e->getMessage()]);
            throw $e;
        }
    }

    /**
     * Revoke the access token.
     *
     * @param string $accessToken
     * @return bool
     */
    public function revokeToken(string $accessToken): bool
    {
        if (!$this->revokeUri) {
            Log::warning('revoke_uri is not configured, skipping token revocation');
            return false;
        }

        try {
            $response = $this->httpClient->withToken($accessToken)->post($this->buildUrl($this->revokeUri));

            if ($response->successful()) {
                $this->clearNavigationMenu();
                Log::info('SSO token revoked successfully');
                return true;
            }

            Log::warning('Failed to revoke SSO token', ['status' => $response->status()]);
            return false;
        } catch (\Exception $e) {
            Log::error('Error revoking SSO token', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Save the navigation menu to the session.
     *
     * @param mixed $data
     * @return void
     */
    public function saveNavigation(mixed $data): void
    {
        session()->put(self::NAVIGATION_CACHE_KEY, $data);
    }

    /**
     * Save the SSO token to the session.
     *
     * @param string $tokenInfo
     * @return void
     */
    public function saveSSOToken(string $tokenInfo): void
    {
        session()->put($this->tokenKey, $tokenInfo);
    }

    /**
     * Get the SSO token from the session.
     *
     * @return string
     */
    public function getSSOToken(): string
    {
        return session($this->tokenKey, '');
    }

    /**
     * Clear the SSO token from the session.
     *
     * @return void
     */
    public function clearSSOToken(): void
    {
        session()->forget($this->tokenKey);
    }

    /**
     * Force logout a user by identifier.
     *
     * @param string $identifier
     * @return bool
     */
    public function forceLogout(string $identifier): bool
    {
        try {
            $userClass = config('sso-client.user_model', 'App\\Models\\User');

            if (!class_exists($userClass)) {
                Log::error('User model class not found for force logout', ['model' => $userClass]);
                return false;
            }

            $user = $userClass::where('email', $identifier)->first();

            if (!$user) {
                Log::warning('User not found for force logout', ['identifier' => $identifier]);
                return false;
            }

            $tokenKey = config('sso-client.token_key_with_user_id', false) 
                ? $this->tokenKey . '_' . $user->id 
                : $this->tokenKey;

            session()->forget($tokenKey);
            $this->clearNavigationMenu();
            $this->deleteUserSessions($user->id);

            Log::info('User force logged out by SSO server', [
                'user_id' => $user->id,
                'email' => $user->email,
                'identifier' => $identifier,
            ]);

            return true;
        } catch (\Exception $e) {
            Log::error('Error force logging out user', ['error' => $e->getMessage(), 'identifier' => $identifier]);
            return false;
        }
    }

    /**
     * Delete user sessions from the database.
     *
     * @param int $userId
     * @return bool
     */
    protected function deleteUserSessions(int $userId): bool
    {
        try {
            DB::table(config('session.table'))->where('user_id', $userId)->delete();
            return true;
        } catch (\Exception $e) {
            Log::error('Failed to delete user sessions from database', ['user_id' => $userId, 'error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Build the full URL for an endpoint.
     *
     * @param string $endpoint
     * @return string
     */
    private function buildUrl(string $endpoint): string
    {
        return rtrim($this->serverUrl, '/') . '/' . ltrim($endpoint, '/');
    }

    /**
     * Default method to create or update a user.
     *
     * @param array $userData
     * @return mixed
     * @throws \Exception
     */
    private function createOrUpdateUserDefault(array $userData): mixed
    {
        $userClass = config('sso-client.user_model', 'App\\Models\\User');

        if (!class_exists($userClass)) {
            throw new \Exception("User model class {$userClass} not found. Please provide a callback or configure user_model in config.");
        }

        return $userClass::updateOrCreate(
            ['email' => $userData['email']],
            [
                'name' => $userData['name'] ?? $userData['email'],
                'phone_number' => $userData['phone_number'] ?? null,
            ]
        );
    }

    /**
     * Create a configured HTTP client.
     *
     * @return \Illuminate\Http\Client\PendingRequest
     */
    private function createHttpClient(): PendingRequest
    {
        $client = Http::timeout(30)
            ->retry(3, 100)
            ->withHeaders(['Accept' => 'application/json', 'Content-Type' => 'application/json']);

        if (!config('sso-client.verify_ssl', false)) {
            $client = $client->withoutVerifying()->withOptions(['verify' => false]);
        }

        return $client;
    }
}
