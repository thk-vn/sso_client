<?php

use Illuminate\Support\Facades\Route;
use THKHD\SsoClient\Http\Controllers\SSOClientController;

Route::group(['prefix' => 'sso-client', 'as' => 'sso-client.'], function () {
    Route::get('login', [SSOClientController::class, 'redirectToSSOServer'])->name('login');
    Route::get('callback', [SSOClientController::class, 'handleCallback'])->name('callback');
    Route::post('logout', [SSOClientController::class, 'logout'])->name('logout');
});
