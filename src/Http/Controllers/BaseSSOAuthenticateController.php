<?php

namespace THKHD\SsoClient\Http\Controllers;

use Illuminate\Contracts\View\View;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use THKHD\SsoClient\Services\SSOClientService;

class BaseSSOAuthenticateController extends Controller
{
    protected const STATE_SESSION_KEY = 'sso_state';
    protected const STATE_LENGTH = 40;

    /**
     * Create a new controller instance.
     *
     * @param \THKHD\SsoClient\Services\SSOClientService $ssoService
     */
    public function __construct(protected SSOClientService $ssoService)
    {
    }

    /**
     * Show the login form.
     *
     * @return \Illuminate\Contracts\View\View
     */
    public function showLoginForm(): View
    {
        return view(config('sso-client.login_view', 'auth.login'));
    }

    /**
     * Redirect the user to the SSO provider.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function redirectToSSO(Request $request): RedirectResponse
    {
        $state = Str::random(self::STATE_LENGTH);
        $request->session()->put(self::STATE_SESSION_KEY, $state);

        return redirect($this->ssoService->buildAuthorizationUrl($state, $this->authorizationExtraParams($request)));
    }

    /**
     * Handle the callback from the SSO provider.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function callback(Request $request): RedirectResponse
    {
        try {
            $this->validateState($request);

            $tokenData = $this->ssoService->getAccessToken($request->code);
            $accessToken = $tokenData['access_token'];
            $userInfo = $this->ssoService->getUser($accessToken);
            $user = $this->ssoService->createOrUpdateUser($userInfo, $this->userSyncCallback());

            $this->afterUserSynced($user, $userInfo, $request);

            try {
                $this->ssoService->storeNavigationMenu($accessToken, $this->resolveLocale($request));
            } catch (\Exception $e) {
                return $this->handleStoreNavigationException($e, $user, $request);
            }

            return $this->handleAuthenticated($request, $user, $userInfo, $accessToken);
        } catch (ValidationException $e) {
            Log::warning('SSO callback validation failed', ['errors' => $e->errors()]);
            return redirect()->route($this->loginRoute())
                ->withErrors($e->errors())
                ->with('error', $e->getMessage());
        } catch (\Exception $e) {
            Log::error('SSO authentication failed', [
                'error' => $e->getMessage(),
                'code' => $request->code ?? null,
                'state' => $request->state ?? null,
            ]);
            return redirect()->route($this->loginRoute())->with('error', $e->getMessage());
        }
    }

    /**
     * Log the user out of the application.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function logout(Request $request): RedirectResponse
    {
        try {
            $this->beforeLogout($request);

            $accessToken = $request->session()->get('sso_token');
            if ($accessToken) {
                $this->ssoService->revokeToken($accessToken);
            }

            $this->ssoService->clearNavigationMenu();
            $this->ssoService->clearSSOToken();
            Auth::logout();
            $request->session()->flush();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            Log::info('User logged out successfully');
        } catch (\Exception $e) {
            Log::error('Logout failed', ['error' => $e->getMessage()]);
        }

        return redirect()->route($this->loginRoute());
    }

    /**
     * Switch the application language.
     *
     * @param \Illuminate\Http\Request $request
     * @param string $language
     * @return \Illuminate\Http\RedirectResponse
     */
    public function switchLanguage(Request $request, string $language): RedirectResponse
    {
        session()->put('locale', $language);

        $accessToken = session()->get('sso_token');
        if ($accessToken) {
            try {
                $this->ssoService->storeNavigationMenu($accessToken, $language);
            } catch (\Exception $e) {
                return $this->handleStoreNavigationException($e, Auth::user(), $request);
            }
        }

        return redirect()->back();
    }

    /**
     * Force logout a user by email or user ID.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function forceLogout(Request $request): JsonResponse
    {
        try {
            $identifier = $request->input('email') ?? $request->input('user_id');

            if (!$identifier) {
                return response()->json(['success' => false, 'message' => 'Email or user_id is required'], 400);
            }

            $result = $this->ssoService->forceLogout($identifier);

            return response()->json([
                'success' => $result,
                'message' => $result ? 'User logged out successfully' : 'Failed to logout user',
                'identifier' => $identifier,
            ], $result ? 200 : 404);
        } catch (\Exception $e) {
            Log::error('Force logout failed', ['error' => $e->getMessage(), 'request' => $request->all()]);
            return response()->json(['success' => false, 'message' => 'Internal server error'], 500);
        }
    }

    /**
     * Get the route to the login page.
     *
     * @return string
     */
    protected function loginRoute(): string
    {
        return config('sso-client.routes.login', 'login');
    }

    /**
     * Get the post-login redirect path.
     *
     * @return string
     */
    protected function redirectPath(): string
    {
        return config('sso-client.redirect_path', '/');
    }

    /**
     * Get extra parameters for the authorization URL.
     *
     * @param \Illuminate\Http\Request $request
     * @return array
     */
    protected function authorizationExtraParams(Request $request): array
    {
        return [];
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }

    /**
     * Get the callback to sync the user.
     *
     * @return callable|null
     */
    protected function userSyncCallback(): ?callable
    {
        return null;
    }

    /**
     * Handle actions after the user has been synced.
     *
     * @param mixed $user
     * @param array $userInfo
     * @param \Illuminate\Http\Request $request
     * @return void
     */
    protected function afterUserSynced(mixed $user, array $userInfo, Request $request): void
    {
    }

    /**
     * Handle actions before the user is logged out.
     *
     * @param \Illuminate\Http\Request $request
     * @return void
     */
    protected function beforeLogout(Request $request): void
    {
    }

    /**
     * Handle the authenticated user.
     *
     * @param \Illuminate\Http\Request $request
     * @param mixed $user
     * @param array $userInfo
     * @param string $accessToken
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function handleAuthenticated(Request $request, mixed $user, array $userInfo, string $accessToken): RedirectResponse
    {
        $remember = $request->cookies->get('remember', false);
        $this->guard()->login($user, $remember);

        $request->session()->put('sso_user', true);
        $request->session()->put('sso_token', $accessToken);
        $request->session()->put('sso_permissions', $userInfo['permissions'] ?? []);
        $request->session()->put('sso_is_super_admin', $userInfo['is_super_admin'] ?? false);

        if (config('sso-client.save_token_flg', true)) {
            $this->ssoService->saveSSOToken($accessToken);
        }

        return redirect()->intended($this->redirectPath());
    }

    /**
     * Handle exceptions when storing the navigation menu.
     *
     * @param \Exception $exception
     * @param mixed $user
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function handleStoreNavigationException(\Exception $exception, mixed $user, Request $request): RedirectResponse
    {
        Log::warning('User does not have permission for this client', [
            'user_id' => $user->id ?? null,
            'email' => $user->email ?? null,
            'error' => $exception->getMessage(),
        ]);

        $this->logout($request);

        return redirect()->route(config('sso-client.routes.login_show', 'login.show'))
            ->with('error', 'Page cannot be accessed.');
    }

    /**
     * Resolve the locale for the user.
     *
     * @param \Illuminate\Http\Request $request
     * @return string
     */
    protected function resolveLocale(Request $request): string
    {
        return $request->session()->get('locale', config('app.locale'));
    }

    /**
     * Validate the state parameter.
     *
     * @param \Illuminate\Http\Request $request
     * @return void
     *
     * @throws \Symfony\Component\HttpKernel\Exception\HttpException
     */
    protected function validateState(Request $request): void
    {
        $sessionState = $request->session()->pull(self::STATE_SESSION_KEY);
        $requestState = $request->state;

        if (!$this->ssoService->validateState($sessionState, $requestState)) {
            Log::warning('Invalid state detected in SSO callback', [
                'session_state' => $sessionState ? 'present' : 'missing',
                'request_state' => $requestState ? 'present' : 'missing',
            ]);
            abort(403);
        }
    }
}

