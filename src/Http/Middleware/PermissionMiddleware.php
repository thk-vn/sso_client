<?php

namespace THKHD\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class PermissionMiddleware
{
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

    protected function getPermissionForRoute(?string $routeName): string|array|null
    {
        if (!$routeName) {
            return null;
        }

        return $this->getRoutePermissions()[$routeName] ?? null;
    }

    protected function getRoutePermissions(): array
    {
        return config('sso-client.route_permissions', []);
    }

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

    protected function getUserPermissions(Request $request): array
    {
        return $request->session()->get('sso_permissions', []);
    }

    protected function isSuperAdmin(Request $request): bool
    {
        return $request->session()->get('sso_is_super_admin', false);
    }

    protected function checkSinglePermission(array $userPermissions, string $requiredPermission): bool
    {
        return in_array($requiredPermission, $userPermissions);
    }

    protected function getNoPermissionMessage(): string
    {
        return 'You do not have permission to access this page.';
    }
}

