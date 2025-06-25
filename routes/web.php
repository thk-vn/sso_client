<?php

use Illuminate\Support\Facades\Route;
use THKHD\SsoClient\Http\Controllers\SSOClientController;

Route::middleware([])->group(function () {
    Route::group(['prefix' => 'sso-client', 'as' => 'sso-client.'], function () {
        Route::post('login', [SSOClientController::class, 'redirectToSSOServer'])->name('login');
        Route::post('logout', [SSOClientController::class, 'logout'])->name('logout');
        Route::get('callback', [SSOClientController::class, 'handleCallback'])->name('callback');
    });
});