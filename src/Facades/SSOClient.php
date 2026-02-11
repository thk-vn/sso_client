<?php

namespace THKHD\SsoClient\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * Facade for the SSO Client service.
 *
 * @method static string buildAuthorizationUrl(string $state, array $extraParams = [])
 * @method static array getAccessToken(string $code)
 * @method static array getUser(string $accessToken)
 * @method static mixed createOrUpdateUser(array $userInfo, ?callable $syncCallback = null)
 * @method static void storeNavigationMenu(string $accessToken, string $locale)
 * @method static void clearNavigationMenu()
 * @method static void saveSSOToken(string $accessToken)
 * @method static void clearSSOToken()
 * @method static bool validateState(?string $sessionState, ?string $requestState)
 * @method static bool revokeToken(string $accessToken)
 * @method static bool forceLogout(string $identifier)
 *
 * @see \THKHD\SsoClient\Services\SSOClientService
 */
class SSOClient extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'sso-client';
    }
}
