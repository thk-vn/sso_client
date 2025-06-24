<?php

namespace THKHD\SsoClient\Http\Controllers;

use Illuminate\Routing\Controller;

class SSOClientController extends Controller
{
    public function redirectToSSOServer()
    {
        return 'ok';
    }
}