<?php

namespace THKHD\SsoClient;

use Illuminate\Support\ServiceProvider;

class SSOClientServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
    }
}
