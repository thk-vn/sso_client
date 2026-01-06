<?php

namespace THKHD\SsoClient\View\Components;

use Illuminate\Support\Facades\Session;
use Illuminate\View\Component;
use THKHD\SsoClient\SSOClientManager;

class NavigationMenu extends Component
{
    /**
     * Static cache to prevent multiple session reads in the same request.
     * This is reset on each new HTTP request automatically.
     */
    private static ?string $cachedNavigation = null;
    private static bool $hasChecked = false;

    /**
     * Create a new component instance.
     * No dependency injection to reduce overhead - we read directly from session.
     */
    public function __construct()
    {
        // Component is lightweight - no service injection needed
        // Navigation is already fetched and stored in session by RefreshNavigationMiddleware
    }

    /**
     * Get the view / contents that represent the component.
     */
    public function render(): string
    {
        // Early return: Check if navigation is enabled (fastest check first)
        if (!config('sso-client.navigation_enabled', true)) {
            return '';
        }

        if (self::$hasChecked) {
            return self::$cachedNavigation ?? '';
        }

        // Mark as checked to prevent further checks in this request
        self::$hasChecked = true;
        $navigation = Session::get(SSOClientManager::NAVIGATION_CACHE_KEY);

        if (empty($navigation) || !is_string($navigation)) {
            self::$cachedNavigation = '';
            return '';
        }

        self::$cachedNavigation = $navigation;
        return $navigation;
    }
}
