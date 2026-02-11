<?php

namespace THKHD\SsoClient;

use Illuminate\Support\ServiceProvider;
use THKHD\SsoClient\Console\InstallSSOClientCommand;
use THKHD\SsoClient\Services\SSOClientService;
use THKHD\SsoClient\SSOClientManager;
use THKHD\SsoClient\View\Components\NavigationMenu;

class SSOClientServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->app->singleton(SSOClientService::class, fn () => new SSOClientService());
        $this->app->singleton(SSOClientManager::class, fn ($app) => $app->make(SSOClientService::class));
        $this->app->alias(SSOClientService::class, 'sso-client');
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->singleton('sso-client', fn($app) => new SSOClientManager());
        $this->mergeConfigFrom(__DIR__.'/../config/sso-client.php', 'sso-client');
        $this->publishes([__DIR__.'/../config/sso-client.php' => config_path('sso-client.php')], 'sso-client-config');

        // Load views from package
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'sso-client');

        // Register View Component
        $this->loadViewComponentsAs('sso', [NavigationMenu::class]);

        if ($this->app->runningInConsole()) {
            $this->commands([InstallSSOClientCommand::class]);
        }
    }
}
