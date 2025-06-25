<?php

namespace THKHD\SsoClient\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\URL;

class SSOClientController extends Controller
{
    /**
     * Redirect To SSO Server
     * 
     * @param \Illuminate\Http\Request $request
     * @return mixed|\Illuminate\Http\RedirectResponse
     */
    public function redirectToSSOServer(Request $request)
    {
        $query = http_build_query([
            'client_id' => config('sso-client.client_id'),
            'redirect_uri' => config('sso-client.redirect_uri'),
            'response_type' => 'code',
            'state' => '',
        ]);
        $ssoAuthUrl = rtrim(config('sso-client.server_url'), '/') . '/oauth/authorize';

        return redirect()->away("{$ssoAuthUrl}?{$query}");
    }
    
    /**
     * Handle Callback
     * 
     * @param \Illuminate\Http\Request $request
     */
    public function handleCallback(Request $request)
    {
        try {
            $userInfo = app('sso-client')->fetchUserFromCode(
                $request->query('code'),
                config('sso-client.redirect_uri')
            );

            $url = URL::signedRoute(config('sso-client.user_resolver'), [
                'data' => encrypt($userInfo),
            ]);

            return redirect($url);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'SSO Callback Failed',
                'message' => $e->getMessage()
            ], 500);
        }
    }

    public function logout()
    {
        return 'logout'; 
    }
}