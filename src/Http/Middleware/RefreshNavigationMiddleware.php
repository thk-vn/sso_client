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
    public function __construct(private SSOClientService $ssoService)
    {
    }

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

    private function shouldSkip(Request $request): bool
    {
        return Auth::guest() || $request->routeIs(...config('sso-client.middleware.skip_routes', []));
    }

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

