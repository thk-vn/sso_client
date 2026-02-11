<?php

namespace THKHD\SsoClient\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;

class InstallSSOClientCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'sso-client:install 
                            {--skip-config : Skip publishing config file}
                            {--skip-routes : Skip creating routes file}
                            {--force : Force overwrite existing files without asking}
                            {--update : Update existing config file by merging with new values}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and setup SSO Client package (publish config, create routes, etc.)';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $this->info('🚀 Installing SSO Client Package...');
        $this->newLine();

        // Step 1: Publish config
        if (!$this->option('skip-config')) {
            $this->info('📝 Step 1: Publishing config file...');
            $this->publishConfig();
        } else {
            $this->info('⏭  Skipping config publish');
        }

        $this->newLine();

        // Step 2: Create routes file
        if (!$this->option('skip-routes')) {
            $this->info('🛣️  Step 2: Creating routes file...');
            $this->createRoutesFile();
        } else {
            $this->info('⏭  Skipping routes creation');
        }

        $this->newLine();

        // Step 3: Update .env file
        $this->info('📝 Step 3: Updating .env file...');
        $this->updateEnvFile();

        $this->newLine();

        // Step 4: Load routes file
        $this->info('🔄 Step 4: Loading routes file...');
        $this->loadRoutesFile();

        $this->newLine();

        // Step 5: Register middleware
        $this->info('🛡️  Step 5: Registering middleware...');
        $this->registerMiddleware();

        $this->newLine();

        // Step 6: Configure admin check
        $this->info('⚙️  Step 6: Configuring admin check...');
        $this->configureAdminCheck();

        $this->newLine();
        $this->info('✅ SSO Client package installed successfully!');
        $this->newLine();

        $this->displayNextSteps();

        return self::SUCCESS;
    }

    /**
     * Publish config file with options for existing files.
     *
     * @return void
     */
    protected function publishConfig(): void
    {
        $configPath = config_path('sso-client.php');
        $configExists = File::exists($configPath);

        // If config doesn't exist, just publish it
        if (!$configExists) {
            Artisan::call('vendor:publish', [
                '--tag' => 'sso-client-config',
            ]);
            $this->info('   ✓ Config published to: config/sso-client.php');
            return;
        }

        // Config file already exists
        $this->warn('   ⚠️  Config file already exists at: config/sso-client.php');

        // If --force option is used, directly overwrite
        if ($this->option('force')) {
            Artisan::call('vendor:publish', [
                '--tag'   => 'sso-client-config',
                '--force' => true,
            ]);
            $this->info('   ✓ Config file overwritten (--force option used)');
            return;
        }

        // If --update option is used, merge configs
        if ($this->option('update')) {
            $this->mergeConfigFile($configPath);
            return;
        }

        // Ask user what to do
        $choice = $this->choice(
            'What would you like to do?',
            [
                'skip' => 'Skip (keep existing file)',
                'overwrite' => 'Overwrite existing file',
                'update' => 'Update (merge new values with existing)',
            ],
            'skip'
        );

        switch ($choice) {
            case 'skip':
                $this->info('   ⏭  Skipping config publish (keeping existing file)');
                break;

            case 'overwrite':
                Artisan::call('vendor:publish', [
                    '--tag'   => 'sso-client-config',
                    '--force' => true,
                ]);
                $this->info('   ✓ Config file overwritten');
                break;

            case 'update':
                $this->mergeConfigFile($configPath);
                break;
        }
    }

    /**
     * Merge new config values with existing config file.
     *
     * @param string $configPath
     * @return void
     */
    protected function mergeConfigFile(string $configPath): void
    {
        // Read existing config
        $existingConfig = require $configPath;
        
        // Get new config from package
        $packageConfigPath = __DIR__.'/../../config/sso-client.php';
        $newConfig = require $packageConfigPath;

        // Merge configs recursively
        // New keys from package will be added, existing keys will be preserved
        $mergedConfig = $this->arrayMergeRecursiveDistinct($newConfig, $existingConfig);

        // Write merged config back to file with proper formatting
        $configContent = $this->formatConfigArray($mergedConfig);
        File::put($configPath, $configContent);

        $this->info('   ✓ Config file updated (merged with existing values)');
        $this->warn('   ⚠️  Please review the config file to ensure all values are correct!');
    }

    /**
     * Recursively merge two arrays, preserving existing values.
     * New keys from $array1 will be added, but existing keys in $array2 take precedence.
     * @param array $array1
     * @param array $array2
     * @return array
     */
    protected function arrayMergeRecursiveDistinct(array $array1, array $array2): array
    {
        $merged = $array1;

        foreach ($array2 as $key => $value) {
            if (is_array($value) && isset($merged[$key]) && is_array($merged[$key])) {
                $merged[$key] = $this->arrayMergeRecursiveDistinct($merged[$key], $value);
            } else {
                $merged[$key] = $value;
            }
        }

        foreach ($array1 as $key => $value) {
            if (!isset($merged[$key])) {
                $merged[$key] = $value;
            }
        }

        return $merged;
    }

    /**
     * Format config array as PHP code.
     * @param array $config
     * @return string
     */
    protected function formatConfigArray(array $config): string
    {
        $content = var_export($config, true);
        $content = preg_replace(['/array\s*\(/', '/\)\s*$/', '/\)\s*,/', '/\)\s*;/'], ['[', ']', '],', '];'], $content);
        return "<?php\n\nreturn " . $content . ";\n";
    }

    /**
     * Create routes file with SSO routes.
     *
     * @return void
     */
    protected function createRoutesFile(): void
    {
        $routesPath = base_path('routes/sso-client.php');
        $routesStub = __DIR__.'/../../stubs/routes.stub';

        // Check if routes file already exists
        if (File::exists($routesPath) && !$this->option('force')) {
            if (!$this->confirm('Routes file already exists. Overwrite?', false)) {
                $this->warn('   ⏭  Skipping routes file creation');
                return;
            }
        }

        // Create stub if doesn't exist
        if (!File::exists($routesStub)) {
            $this->createRoutesStub($routesStub);
        }

        // Copy stub to routes
        File::copy($routesStub, $routesPath);
        $this->info('   ✓ Routes file created at: routes/sso-client.php');

        // Check if routes are loaded in RouteServiceProvider or bootstrap/app.php
        $this->checkRoutesLoaded();
    }

    /**
     * Create routes stub file.
     *
     * @param string $stubPath
     * @return void
     */
    protected function createRoutesStub(string $stubPath): void
    {
        $stubDir = dirname($stubPath);
        if (!File::exists($stubDir)) {
            File::makeDirectory($stubDir, 0755, true);
        }

        $stubContent = <<<'PHP'
<?php

use Illuminate\Support\Facades\Route;
use THKHD\SsoClient\Http\Controllers\SSOAuthenticateController;
use THKHD\SsoClient\Http\Middleware\ValidateSSOSecretMiddleware;

/*
|--------------------------------------------------------------------------
| SSO Client Routes
|--------------------------------------------------------------------------
|
| Authentication routes for SSO Client package.
| You can customize these routes or move them to your existing routes files.
|
*/

// Guest routes
Route::middleware('guest')->group(function () {
    Route::get('login', [SSOAuthenticateController::class, 'showLoginForm'])
        ->name('login.show');

    Route::post('login', [SSOAuthenticateController::class, 'redirectToSSO'])
        ->name('login');

    Route::get('callback', [SSOAuthenticateController::class, 'callback'])
        ->name('sso.callback');
});

// Authenticated routes
Route::middleware('auth')->group(function () {
    Route::post('logout', [SSOAuthenticateController::class, 'logout'])
        ->name('logout');

    Route::get('switch-language/{language}', [SSOAuthenticateController::class, 'switchLanguage'])
        ->name('sso.switch-language');
});

// Remote logout endpoint - called by SSO server to force logout users
Route::middleware([ValidateSSOSecretMiddleware::class])->group(function () {
    Route::post('remote-logout', [SSOAuthenticateController::class, 'forceLogout'])
        ->name('sso.remote-logout');
    
    // Alternative route name
    Route::post('force-logout', [SSOAuthenticateController::class, 'forceLogout'])
        ->name('sso.force-logout');
});

PHP;

        File::put($stubPath, $stubContent);
    }

    /**
     * Check if routes are loaded and provide instructions.
     * @return void
     */
    protected function checkRoutesLoaded(): void
    {
        $bootstrapAppPath = base_path('bootstrap/app.php');
        $webRoutesPath = base_path('routes/web.php');

        $routesLoaded = false;

        if (File::exists($bootstrapAppPath)) {
            $content = File::get($bootstrapAppPath);
            $routesLoaded = str_contains($content, 'sso-client.php') || str_contains($content, 'routes/sso-client.php');
        }

        if (!$routesLoaded && File::exists($webRoutesPath)) {
            $routesLoaded = str_contains(File::get($webRoutesPath), "require __DIR__.'/sso-client.php'");
        }

        if (!$routesLoaded) {
            $this->newLine();
            $this->warn('⚠️  Routes file created but not loaded yet!');
            $this->line('   Add this to your routes/web.php or bootstrap/app.php:');
            $this->line('   require __DIR__.\'/sso-client.php\';');
        } else {
            $this->info('   ✓ Routes are already loaded');
        }
    }

    /**
     * Update .env file with SSO configuration.
     * @return void
     */
    protected function updateEnvFile(): void
    {
        $envPath = base_path('.env');

        if (!File::exists($envPath)) {
            $this->warn('   ⚠️  .env file not found. Please create it manually.');
            return;
        }

        $envContent = File::get($envPath);
        $envVars = [
            'SSO_SERVER_URL' => 'https://your-sso-server.com',
            'SSO_CLIENT_ID' => 'your-client-id',
            'SSO_CLIENT_SECRET' => 'your-client-secret',
            'SSO_REDIRECT_URI' => config('app.url') . '/callback',
            'SSO_REMOTE_LOGOUT_SECRET' => bin2hex(random_bytes(32)),
        ];

        $updated = false;
        foreach ($envVars as $key => $defaultValue) {
            if (!preg_match("/^{$key}=/m", $envContent)) {
                $envContent .= "\n{$key}={$defaultValue}\n";
                $updated = true;
            }
        }

        if ($updated) {
            File::put($envPath, $envContent);
            $this->info('   ✓ Added SSO configuration to .env file');
            $this->warn('   ⚠️  Please update the values with your actual SSO credentials!');
        } else {
            $this->info('   ✓ SSO configuration already exists in .env file');
        }
    }

    /**
     * Load routes file automatically.
     * @return void
     */
    protected function loadRoutesFile(): void
    {
        $ssoRoutesPath = base_path('routes/sso-client.php');

        if (!File::exists($ssoRoutesPath)) {
            $this->warn('   ⚠️  Routes file not found. Please run without --skip-routes option.');
            return;
        }

        $webRoutesPath = base_path('routes/web.php');
        if (File::exists($webRoutesPath)) {
            $content = File::get($webRoutesPath);
            if (!str_contains($content, "require __DIR__.'/sso-client.php'")) {
                File::put($webRoutesPath, $content . "\n// SSO Client routes\nrequire __DIR__.'/sso-client.php';\n");
                $this->info('✓ Added routes to routes/web.php');
                return;
            }
            $this->info('✓ Routes already loaded in routes/web.php');
            return;
        }

        $bootstrapAppPath = base_path('bootstrap/app.php');
        if (File::exists($bootstrapAppPath)) {
            $content = File::get($bootstrapAppPath);
            if (str_contains($content, 'sso-client.php')) {
                $this->info('   ✓ Routes already loaded in bootstrap/app.php');
                return;
            }

            if (preg_match("/web:\s*__DIR__\.'\/\.\.\/routes\/web\.php'/", $content)) {
                $content = preg_replace(
                    "/web:\s*__DIR__\.'\/\.\.\/routes\/web\.php'/",
                    "web: [__DIR__.'/../routes/web.php', __DIR__.'/../routes/sso-client.php']",
                    $content
                );
                File::put($bootstrapAppPath, $content);
                $this->info('   ✓ Added routes to bootstrap/app.php');
                return;
            }
        }

        $this->warn('   ⚠️  Could not auto-load routes. Please add manually:');
        $this->line('      require __DIR__.\'/sso-client.php\';');
    }

    /**
     * Register middleware in bootstrap/app.php.
     *
     * @return void
     */
    protected function registerMiddleware(): void
    {
        $bootstrapAppPath = base_path('bootstrap/app.php');
        
        if (!File::exists($bootstrapAppPath)) {
            $this->warn('   ⚠️  bootstrap/app.php not found (Laravel 11+).');
            return;
        }

        $content = File::get($bootstrapAppPath);

        // Check if middleware already registered
        if (str_contains($content, 'RefreshNavigationMiddleware') && 
            str_contains($content, 'AdminMiddleware') && 
            str_contains($content, 'PermissionMiddleware')) {
            $this->info('   ✓ Middleware already registered');
            return;
        }

        // Add use statements if not present
        $useStatements = [
            'use THKHD\\SsoClient\\Http\\Middleware\\AdminMiddleware;',
            'use THKHD\\SsoClient\\Http\\Middleware\\PermissionMiddleware;',
            'use THKHD\\SsoClient\\Http\\Middleware\\RefreshNavigationMiddleware;',
        ];

        foreach ($useStatements as $use) {
            if (!str_contains($content, $use)) {
                // Add after last use statement before namespace or class
                $lines = explode("\n", $content);
                $lastUseIndex = 0;
                for ($i = 0; $i < count($lines); $i++) {
                    if (preg_match('/^use\s+/', $lines[$i])) {
                        $lastUseIndex = $i;
                    }
                }
                array_splice($lines, $lastUseIndex + 1, 0, $use);
                $content = implode("\n", $lines);
            }
        }

        // Add middleware registration
        if (preg_match("/->withMiddleware\s*\(function\s*\(Middleware\s+\$middleware\)\s*\{/", $content)) {
            // Check if RefreshNavigationMiddleware is already in web array
            if (!str_contains($content, 'RefreshNavigationMiddleware::class')) {
                // Add to web middleware array
                $content = preg_replace(
                    "/\$middleware->web\(\[([^\]]+)\]/",
                    "\$middleware->web([$1, RefreshNavigationMiddleware::class",
                    $content
                );
            }

            // Check if alias already exists
            if (!str_contains($content, "'admin'") || !str_contains($content, "'permission'")) {
                // Add alias if not exists
                if (preg_match("/\$middleware->alias\(\[/", $content)) {
                    // Check if admin or permission already exists
                    if (!str_contains($content, "'admin'")) {
                        $content = preg_replace(
                            "/\$middleware->alias\(\s*\[/",
                            "\$middleware->alias([\n            'admin' => AdminMiddleware::class,\n            ",
                            $content
                        );
                    }
                    if (!str_contains($content, "'permission'")) {
                        $content = preg_replace(
                            "/'admin'\s*=>\s*AdminMiddleware::class,/",
                            "'admin' => AdminMiddleware::class,\n            'permission' => PermissionMiddleware::class,",
                            $content
                        );
                    }
                } else {
                    // Add new alias block before closing brace
                    $content = preg_replace(
                        "/(\s+)(\}\);)/",
                        "$1\$middleware->alias([\n$1    'admin' => AdminMiddleware::class,\n$1    'permission' => PermissionMiddleware::class,\n$1]);$2",
                        $content,
                        1
                    );
                }
            }
        } else {
            // Add withMiddleware block after withRouting
            $content = preg_replace(
                "/(->withRouting\([^)]+\))/",
                "$1\n    ->withMiddleware(function (Middleware \$middleware) {\n        \$middleware->web([RefreshNavigationMiddleware::class]);\n        \$middleware->alias([\n            'admin' => AdminMiddleware::class,\n            'permission' => PermissionMiddleware::class,\n        ]);\n    })",
                $content
            );
        }

        File::put($bootstrapAppPath, $content);
        $this->info('   ✓ Middleware registered in bootstrap/app.php');
    }

    /**
     * Configure admin check in AppServiceProvider.
     *
     * @return void
     */
    protected function configureAdminCheck(): void
    {
        $appServiceProviderPath = app_path('Providers/AppServiceProvider.php');
        
        if (!File::exists($appServiceProviderPath)) {
            $this->warn('   ⚠️  AppServiceProvider not found. Skipping admin check configuration.');
            return;
        }

        $content = File::get($appServiceProviderPath);

        // Check if already configured
        if (str_contains($content, "config(['sso-client.admin_check'")) {
            $this->info('   ✓ Admin check already configured');
            return;
        }

        // Add admin check configuration in boot method
        if (preg_match("/public function boot\(\): void\s*\{/", $content)) {
            // Check if already exists
            if (str_contains($content, "config(['sso-client.admin_check'")) {
                $this->info('   ✓ Admin check already configured');
                return;
            }

            // Add after boot method opening brace
            $adminCheckCode = "\n        // Configure SSO admin check\n        config(['sso-client.admin_check' => fn(\$user) => \$user->role === 'admin']);\n";
            
            $content = preg_replace(
                "/(public function boot\(\): void\s*\{)/",
                "$1{$adminCheckCode}",
                $content
            );

            File::put($appServiceProviderPath, $content);
            $this->info('   ✓ Admin check configured in AppServiceProvider');
            $this->warn('   ⚠️  Please customize the admin check logic if needed!');
        } else {
            $this->warn('   ⚠️  Could not find boot() method. Please add manually:');
            $this->line("      config(['sso-client.admin_check' => fn(\$user) => \$user->role === 'admin']);");
        }
    }

    /**
     * Display next steps instructions.
     *
     * @return void
     */
    protected function displayNextSteps(): void
    {
        $this->comment('📋 Final steps:');
        $this->newLine();

        $this->line('1. Update .env file with your actual SSO credentials:');
        $this->line('   - SSO_SERVER_URL');
        $this->line('   - SSO_CLIENT_ID');
        $this->line('   - SSO_CLIENT_SECRET');
        $this->line('   - SSO_REDIRECT_URI');
        $this->line('   - SSO_REMOTE_LOGOUT_SECRET');
        $this->newLine();

        $this->line('2. Customize admin check logic in AppServiceProvider if needed');
        $this->newLine();

        $this->line('3. Ensure your User model has required fields: email, name, phone_number, role');
        $this->newLine();

        $this->info('🎉 Setup complete! Your SSO Client is ready to use.');
        $this->newLine();
    }
}

