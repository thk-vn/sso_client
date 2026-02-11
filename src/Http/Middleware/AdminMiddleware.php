<?php

namespace THKHD\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AdminMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return \Symfony\Component\HttpFoundation\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next): Response|RedirectResponse
    {
        $user = $request->user();

        if (!$user) {
            return redirect()->route(config('sso-client.routes.login_show', 'login.show'));
        }

        if (!$this->isAdmin($user)) {
            return redirect()->route(config('sso-client.routes.dashboard_route', 'dashboard'))
                ->with('warning', __('auth.permission_denied'));
        }

        return $next($request);
    }

    /**
     * Check if the user is an admin.
     *
     * @param mixed $user
     * @return bool
     */
    private function isAdmin($user): bool
    {
        $adminCheck = config('sso-client.admin_check');

        if (is_callable($adminCheck)) {
            return $adminCheck($user);
        }

        if ($adminCheck !== null) {
            return $this->compareRole($user->role ?? null, $adminCheck);
        }

        return $this->compareRole($user->role ?? null, 'admin')
            || ($user->is_super_admin ?? false)
            || session()->get('sso_is_super_admin', false);
    }

    /**
     * Compare the user role with a value.
     *
     * @param mixed $role
     * @param mixed $value
     * @return bool
     */
    private function compareRole($role, $value): bool
    {
        if ($role === $value) {
            return true;
        }

        if (is_object($role) && method_exists($role, 'value')) {
            return $role->value === $value;
        }

        return false;
    }
}

