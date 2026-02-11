<?php

namespace THKHD\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class PermissionMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @param string|null $permission
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function handle(Request $request, Closure $next, ?string $permission = null): Response
    {
        $user = $request->user();

        if (!$user) {
            return redirect()->route(config('sso-client.routes.login_show', 'login.show'));
        }

        $routeName = $request->route()?->getName();
        $requiredPermission = $permission ?? $this->getPermissionForRoute($routeName);

        if (!$requiredPermission) {
            return $next($request);
        }

        if (!$this->hasPermission($request, $requiredPermission)) {
            Log::warning('User does not have permission to access route', [
                'user_id' => $user->id,
                'email' => $user->email,
                'route' => $routeName,
                'required_permission' => $requiredPermission,
            ]);

            abort(403, $this->getNoPermissionMessage());
        }

        return $next($request);
    }

    /**
     * Get the permission required for the current route.
     *
     * @param string|null $routeName
     * @return string|array|null
     */
    protected function getPermissionForRoute(?string $routeName): string|array|null
    {
        if (!$routeName) {
            return null;
        }

        return $this->getRoutePermissions()[$routeName] ?? null;
    }

    /**
     * Get the route permissions configuration.
     *
     * @return array
     */
    protected function getRoutePermissions(): array
    {
        return config('sso-client.route_permissions', []);
    }

    /**
     * Check if the user has the required permission.
     *
     * @param \Illuminate\Http\Request $request
     * @param string|array $requiredPermission
     * @return bool
     */
    protected function hasPermission(Request $request, string|array $requiredPermission): bool
    {
        if ($this->isSuperAdmin($request)) {
            return true;
        }

        $permissions = $this->getUserPermissions($request);

        if (is_array($requiredPermission)) {
            foreach ($requiredPermission as $perm) {
                if ($this->checkSinglePermission($permissions, $perm)) {
                    return true;
                }
            }
            return false;
        }

        return $this->checkSinglePermission($permissions, $requiredPermission);
    }

    /**
     * Get the user's permissions from the session.
     *
     * @param \Illuminate\Http\Request $request
     * @return array
     */
    protected function getUserPermissions(Request $request): array
    {
        return $request->session()->get('sso_permissions', []);
    }

    /**
     * Check if the user is a super admin.
     *
     * @param \Illuminate\Http\Request $request
     * @return bool
     */
    protected function isSuperAdmin(Request $request): bool
    {
        return $request->session()->get('sso_is_super_admin', false);
    }

    /**
     * Check if a single permission exists in the user's permissions.
     *
     * @param array $userPermissions
     * @param string $requiredPermission
     * @return bool
     */
    protected function checkSinglePermission(array $userPermissions, string $requiredPermission): bool
    {
        return in_array($requiredPermission, $userPermissions);
    }

    /**
     * Get the message for permission denied.
     *
     * @return string
     */
    protected function getNoPermissionMessage(): string
    {
        return 'You do not have permission to access this page.';
    }
}

