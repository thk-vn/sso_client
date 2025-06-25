<?php

namespace THKHD\SsoClient;

use Illuminate\Support\ServiceProvider;
use THKHD\SsoClient\SSOClientManager;

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
        $this->app->singleton('sso-client', fn($app) => new SSOClientManager());
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        $this->mergeConfigFrom(__DIR__.'/../config/sso-client.php', 'sso-client');
        $this->publishes([__DIR__.'/../config/sso-client.php' => config_path('sso-client.php')], 'sso-client-config');
    }
}
