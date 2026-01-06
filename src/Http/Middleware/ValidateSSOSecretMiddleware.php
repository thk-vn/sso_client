<?php

namespace THKHD\SsoClient\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

class ValidateSSOSecretMiddleware
{
    public function handle(Request $request, Closure $next): Response
    {
        $secret = config('sso-client.remote_logout_secret');

        if (empty($secret)) {
            Log::warning('SSO remote logout secret not configured. Allowing request without validation.');
            return $next($request);
        }

        $requestSecret = $this->extractSecret($request);

        if (empty($requestSecret)) {
            Log::warning('SSO remote logout request missing secret', [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
            return response()->json(['success' => false, 'message' => 'Unauthorized: Missing secret token'], 401);
        }

        if (!hash_equals($secret, $requestSecret)) {
            Log::warning('SSO remote logout request with invalid secret', [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
            ]);
            return response()->json(['success' => false, 'message' => 'Unauthorized: Invalid secret token'], 401);
        }

        return $next($request);
    }

    private function extractSecret(Request $request): ?string
    {
        $secret = $request->header('X-SSO-Secret')
            ?? $request->header('Authorization')
            ?? $request->input('secret')
            ?? $request->input('token');

        if ($secret && str_starts_with($secret, 'Bearer ')) {
            $secret = substr($secret, 7);
        }

        return $secret;
    }
}

