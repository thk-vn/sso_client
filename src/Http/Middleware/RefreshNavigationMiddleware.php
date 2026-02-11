<?php

namespace THKHD\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;
use THKHD\SsoClient\Services\SSOClientService;

class RefreshNavigationMiddleware
{
    /**
     * Create a new middleware instance.
     *
     * @param \THKHD\SsoClient\Services\SSOClientService $ssoService
     */
    public function __construct(private SSOClientService $ssoService)
    {
    }

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($this->shouldSkip($request)) {
            return $next($request);
        }

        if (!config('sso-client.navigation_enabled', true)) {
            return $next($request);
        }

        $token = $this->ssoService->getSSOToken();

        if (!$token) {
            return $this->forceLogout($request);
        }

        if (!$this->ssoService->getNavigationMenu()) {
            try {
                $this->ssoService->storeNavigationMenu($token, $request->session()->get('locale', config('app.locale')));
            } catch (\Exception $e) {
                Log::warning('User lost permission for this client during navigation refresh', [
                    'user_id' => Auth::id(),
                    'error' => $e->getMessage(),
                ]);
                return $this->forceLogout($request, $e->getMessage());
            }
        }

        return $next($request);
    }

    /**
     * Determine if the middleware should be skipped for the current request.
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    private function shouldSkip(Request $request): bool
    {
        return Auth::guest() || $request->routeIs(...config('sso-client.middleware.skip_routes', []));
    }

    /**
     * Force logout the user and redirect to login page.
     *
     * @param \Illuminate\Http\Request $request
     * @param string|null $error
     * @return \Symfony\Component\HttpFoundation\Response
     */
    private function forceLogout(Request $request, ?string $error = null): Response
    {
        Auth::logout();
        $request->session()->flush();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        $this->ssoService->clearNavigationMenu();
        $this->ssoService->clearSSOToken();

        $redirect = redirect()->route(config('sso-client.routes.login_show', 'login.show'));

        return $error ? $redirect->with('error', $error) : $redirect;
    }
}

