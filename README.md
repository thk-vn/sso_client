
# 📄 Package Laravel xác thực OAuth2 (SSO Client)

## 🔖 Documents

- **Mục tiêu**: [Documents](https://thk-vn.github.io/sso_client/docs/index.html)

## 🔖 1. Mô tả chung

- **Mục tiêu**:  
  Xây dựng một Laravel package đóng vai trò như một **client thư viện OAuth2**, phục vụ việc xác thực người dùng thông qua hệ thống **SSO (Single Sign-On)**.

- **Đối tượng sử dụng**:  
  Các hệ thống Laravel khác (gọi là **client app**) muốn xác thực người dùng thông qua hệ thống **SSO Provider** trung tâm.

- **Kết quả mong đợi**:  
  Một package Laravel hoàn chỉnh, dễ cài đặt và tích hợp, cho phép client app:
  - Redirect người dùng tới SSO để đăng nhập.
  - Nhận token và thông tin người dùng.
  - Tự động xử lý xác thực và lưu thông tin đăng nhập.
  - Gọi được API với token đã nhận.

## ✅ Checklist chức năng hoàn chỉnh

| Tính năng | Trạng thái |
|-----------|------------|
| Cấu trúc package Laravel chuẩn | ✅ |
| Config publish được | ✅ |
| Xử lý callback + token exchange | ✅ |
| Gọi API lấy user info | ✅ |
| Lưu session / token | ✅ |
| Hướng dẫn sử dụng | ✅ |

## ⚙️ 2. Kỹ thuật sử dụng

- **Chuẩn xác thực**: OAuth2 Authorization Code Flow.
- **Laravel version**: Tương thích Laravel 9 trở lên.

## 🔁 3. OAuth2 Flow dành cho Client

### 3.1. Các bước cơ bản:

| Bước | Mô tả |
|------|------|
| 1 | Người dùng truy cập trang cần đăng nhập |
| 2 | Client redirect người dùng đến SSO Provider (Authorization Server) |
| 3 | Người dùng đăng nhập trên SSO Provider |
| 4 | SSO redirect lại về `redirect_uri` của client kèm `code` |
| 5 | Client gửi `code` đến token endpoint để lấy `access_token` |
| 6 | Client dùng `access_token` để gọi API `/user` |
| 7 | Client lưu thông tin user vào session hoặc cache |

## 📦 4. Tính năng chính của Package

| Chức năng | Mô tả |
|-----------|-------|
| `Login Redirect` | Hàm xử lý chuyển hướng người dùng tới SSO |
| `Callback Handler` | Hàm nhận `code`, đổi sang `access_token`, lấy thông tin người dùng |
| `Token Service` | Lưu token, xử lý refresh token (nếu cần) |
| `Get User` | Lấy thông tin người dùng từ token |

## 🧩 5. Cấu trúc Package

```
laravel-sso-client/
├── src/
│   ├── SSOClientServiceProvider.php
│   ├── Facades/
│   │   └── SSOClient.php
│   └── SSOClientManager.php
├── config/
│   └── sso-client.php
├── README.md
├── composer.json
```

## 📘 5. Cách sử dụng package (ví dụ)

### A. Cài đặt
```bash
composer require thk-hd/sso-client
composer require thk-hd/sso-client:dev-main (dev)

# Chạy command để setup tự động (khuyến nghị)
php artisan sso-client:install

# Hoặc setup thủ công
php artisan vendor:publish --tag=sso-client-config
```

### B. Cấu hình `.env`
```env
SSO_SERVER_URL=http://127.0.0.1:8001
SSO_CLIENT_ID=xxxxxxxxxxxxxxxxxx
SSO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxx
SSO_REDIRECT_URI=http://localhost:8000/sso-client/callback
```

### C. Xử lí login (Tham khảo, bạn có thể tuỳ chỉnh thêm)
```php
use THKHD\SsoClient\Facades\SSOClient;

public function login(Request $request)
{
    $state = 'sssssssssssssssssssss';
    $redirectUrl = SSOClient::buildAuthorizationUrl($state);
    return redirect($redirectUrl);
}

public function handleCallback(Request $request)
{
    $code = $request->query('code');
    $state = $request->query('state');
    $stateSso = 'sssssssssssssssssssss';
    if (!$code || !$state) {
        abort(400, 'Missing code or state.');
    }

    if ($state !== $stateSso) {
        abort(403, 'Invalid state detected (CSRF protection).');
    }

    try {
        $tokenResponse = SSOClient::getAccessToken($code);
        $userInfo = SSOClient::user($tokenResponse['access_token']);
    } catch (\Exception $e) {
        logger()->error('SSO Callback Error', ['message' => $e->getMessage()]);
        abort(500, 'SSO Authentication failed.');
    }

    $user = User::where('email', $userInfo['email'] ?? '')->first();
    if (! $user) {
        abort(403, 'Tài khoản chưa được cấp phép để đăng nhập.');
    }
    Auth::login($user);
    return redirect()->intended('/');
}
```

### D. Gọi thông tin người dùng
```php
use THKHD\SsoClient\Facades\SSOClient;

$accessToken = SSOClient::getSSOToken();
$user = SSOClient::getUser($accessToken);
```

## 🔧 6. Các Method có sẵn

### 6.1. Authentication Methods
- `buildAuthorizationUrl(string $state, array $extraParams = [])`: Tạo URL để redirect đến SSO
- `getAccessToken(string $code)`: Lấy access token từ authorization code
- `getUser(string $accessToken)`: Lấy thông tin user từ SSO server
- `user(string $accessToken)`: Alias của `getUser()`
- `validateState(?string $sessionState, ?string $requestState)`: Validate state parameter để chống CSRF

### 6.2. Token Management
- `saveSSOToken(string $token)`: Lưu token vào cache
- `getSSOToken()`: Lấy token từ cache
- `clearSSOToken()`: Xóa token khỏi cache
- `revokeToken(string $accessToken)`: Revoke token trên SSO server

### 6.3. Navigation Menu
- `storeNavigationMenu(string $accessToken, ?string $lang = 'en')`: Lấy và lưu navigation menu từ SSO
- `getNavigationMenu()`: Lấy navigation menu từ session
- `clearNavigationMenu()`: Xóa navigation menu khỏi session

**Xem chi tiết hướng dẫn sử dụng Navigation Menu tại mục [11. Navigation Menu](#-11-navigation-menu)**

### 6.4. User Management
- `createOrUpdateUser(array $userData, ?callable $callback = null)`: Tạo hoặc cập nhật user từ SSO data
  - Nếu không có callback, sẽ tự động sử dụng User model từ config
  - Có thể truyền callback để custom logic tạo/cập nhật user
- `forceLogout(string|int $identifier)`: Force logout user theo email hoặc user_id
  - Được gọi bởi SSO server để force logout user từ xa
  - Tự động clear session, token, và navigation menu

### 6.5. Controller
- `THKHD\SsoClient\Http\Controllers\SSOAuthenticateController`: Controller có sẵn sẵn sàng sử dụng trong routes
- `THKHD\SsoClient\Http\Controllers\BaseSSOAuthenticateController`: Có thể extends để override các hook (`afterUserSynced`, `authorizationExtraParams`, `handleAuthenticated`, v.v.)
  - `forceLogout(Request $request)`: Endpoint để SSO server gọi logout user từ xa

### 6.6. Middleware
- `THKHD\SsoClient\Http\Middleware\RefreshNavigationMiddleware`: Tự động refresh navigation menu từ SSO và đảm bảo token hợp lệ
- `THKHD\SsoClient\Http\Middleware\PermissionMiddleware`: Kiểm tra quyền truy cập dựa trên permissions từ SSO session
  - Có thể extend và override `getRoutePermissions()` để map route với permission
  - Hỗ trợ super admin, parent permission checking, và array permissions
- `THKHD\SsoClient\Http\Middleware\AdminMiddleware`: Kiểm tra user có phải admin không
  - Hỗ trợ configurable admin check logic (closure hoặc string value)
  - Mặc định check role === 'admin' hoặc is_super_admin
- `THKHD\SsoClient\Http\Middleware\ValidateSSOSecretMiddleware`: Xác thực secret token cho remote logout endpoint
  - Bảo vệ route remote-logout khỏi các request không hợp lệ
  - Hỗ trợ secret trong header (X-SSO-Secret, Authorization) hoặc query/body parameter

### 6.7. Service
- `THKHD\SsoClient\Services\SSOClientService`: Service container binding sẵn, có thể inject qua constructor (tương thích với Facade)

## ⚙️ 7. Cấu hình nâng cao

### 7.1. Environment Variables
```env
SSO_SERVER_URL=http://127.0.0.1:8001
SSO_CLIENT_ID=xxxxxxxxxxxxxxxxxx
SSO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxx
SSO_REDIRECT_URI=http://localhost:8000/sso-client/callback
SSO_REVOKE_URI=/oauth/token/refresh
SSO_MENUS_URI=/api/menus
SSO_SAVE_TOKEN_FLG=true
SSO_TOKEN_KEY=sso_token
SSO_TOKEN_KEY_WITH_USER_ID=false
SSO_VERIFY_SSL=false
SSO_USER_MODEL=App\\Models\\User
SSO_LOGIN_VIEW=auth.login
SSO_LOGIN_ROUTE=login
SSO_LOGIN_SHOW_ROUTE=login.show
SSO_REDIRECT_PATH=/
SSO_MSG_PAGE_CANNOT_ACCESSED="Page cannot be accessed."
SSO_MSG_UNAUTHENTICATED="Unauthenticated."
SSO_MSG_NO_PERMISSION="You do not have permission to access this page."
SSO_SESSION_KEY_PERMISSIONS=sso_permissions
SSO_SESSION_KEY_IS_SUPER_ADMIN=sso_is_super_admin
SSO_SESSION_KEY_USER=sso_user
SSO_SESSION_KEY_TOKEN=sso_token
SSO_REMOTE_LOGOUT_SECRET=your-strong-secret-token-here
SSO_REMOTE_LOGOUT_ENABLED=true
```

### 7.2. Config Options
- `token_key_with_user_id`: Nếu `true`, token key sẽ bao gồm user_id (ví dụ: `sso_token_123`)
- `verify_ssl`: Nếu `true`, sẽ verify SSL certificate khi gọi API
- `user_model`: Class name của User model để sử dụng trong `createOrUpdateUser()`
- `login_view`: View hiển thị trang đăng nhập
- `routes.login`, `routes.login_show`: Tên route cho redirect/login form
- `redirect_path`: Đường dẫn sau khi login thành công
- `messages.page_cannot_accessed`, `messages.unauthenticated`: Tuỳ chỉnh message mặc định
- `middleware.skip_routes`: Danh sách route name bỏ qua middleware RefreshNavigation
- `remote_logout_secret`: Secret token để xác thực request từ SSO server (bắt buộc nếu muốn sử dụng remote logout)
  - Nên là chuỗi ngẫu nhiên mạnh, tối thiểu 32 ký tự
  - Tạo bằng: `php -r "echo bin2hex(random_bytes(32));"`
  - Xem chi tiết tại mục 10.2 và 10.3
- `remote_logout_enabled`: Bật/tắt tính năng remote logout (mặc định: true)
- `navigation_enabled`: Bật/tắt tính năng navigation menu từ SSO (mặc định: true)
  - Nếu `false`, middleware `RefreshNavigationMiddleware` sẽ bỏ qua việc fetch và refresh menu
  - Xem chi tiết tại mục 11
- `admin_check`: Closure hoặc string để kiểm tra user có phải admin không
- `routes.dashboard_route`: Route name cho dashboard (dùng trong AdminMiddleware)

## 📝 8. Ví dụ sử dụng đầy đủ

```php
use THKHD\SsoClient\Facades\SSOClient;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

// 1. Redirect to SSO
public function redirectToSSO(Request $request)
{
    $state = Str::random(40);
    $request->session()->put('sso_state', $state);
    $redirectUrl = SSOClient::buildAuthorizationUrl($state);
    return redirect($redirectUrl);
}

// 2. Handle callback
public function handleCallback(Request $request)
{
    $sessionState = $request->session()->pull('sso_state');
    $requestState = $request->query('state');
    
    if (!SSOClient::validateState($sessionState, $requestState)) {
        abort(403, 'Invalid state');
    }
    
    try {
        // Get access token
        $tokenData = SSOClient::getAccessToken($request->code);
        $accessToken = $tokenData['access_token'];
        
        // Get user info
        $userInfo = SSOClient::getUser($accessToken);
        
        // Create or update user
        $user = SSOClient::createOrUpdateUser($userInfo, function($userData) {
            return \App\Models\User::updateOrCreate(
                ['email' => $userData['email']],
                [
                    'name' => $userData['name'] ?? $userData['email'],
                    'phone_number' => $userData['phone_number'] ?? null,
                ]
            );
        });
        
        // Store navigation menu
        $locale = $request->session()->get('locale', 'en');
        SSOClient::storeNavigationMenu($accessToken, $locale);
        
        // Login user
        Auth::login($user, true);
        
        // Store additional session data
        $request->session()->put('sso_token', $accessToken);
        $request->session()->put('sso_permissions', $userInfo['permissions'] ?? []);
        
        return redirect()->intended('/');
    } catch (\Exception $e) {
        logger()->error('SSO authentication failed', ['error' => $e->getMessage()]);
        return redirect()->route('login')->with('error', $e->getMessage());
    }
}

// 3. Logout
public function logout(Request $request)
{
    $accessToken = $request->session()->get('sso_token');
    if ($accessToken) {
        SSOClient::revokeToken($accessToken);
    }
    
    SSOClient::clearNavigationMenu();
    Auth::logout();
    $request->session()->flush();
    
    return redirect()->route('login');
}
```

## 🚀 9. Tích hợp nhanh trong ứng dụng

### 9.1. Sử dụng controller mặc định
```php
use THKHD\SsoClient\Http\Controllers\SSOAuthenticateController;

Route::get('login', [SSOAuthenticateController::class, 'showLoginForm'])->name('login.show');
Route::post('login', [SSOAuthenticateController::class, 'redirectToSSO'])->name('login');
Route::get('auth/callback', [SSOAuthenticateController::class, 'callback'])->name('sso.callback');
Route::post('logout', [SSOAuthenticateController::class, 'logout'])->name('logout');
Route::post('language/{language}', [SSOAuthenticateController::class, 'switchLanguage'])->name('language.switch');

// Remote logout endpoint - được gọi bởi SSO server để force logout user
use THKHD\SsoClient\Http\Middleware\ValidateSSOSecretMiddleware;

Route::middleware([ValidateSSOSecretMiddleware::class])->group(function () {
    Route::post('remote-logout', [SSOAuthenticateController::class, 'forceLogout'])->name('sso.remote-logout');
    // Hoặc route alias
    Route::post('force-logout', [SSOAuthenticateController::class, 'forceLogout'])->name('sso.force-logout');
});
```

Đăng ký middleware refresh navigation:
```php
use THKHD\SsoClient\Http\Middleware\RefreshNavigationMiddleware;

// Trong bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web([RefreshNavigationMiddleware::class]);
})
```

### 9.3. Sử dụng Permission Middleware

**Lưu ý quan trọng:** PermissionMiddleware tự động sử dụng permissions từ SSO session (`sso_permissions`) được lưu sau khi authentication thành công. Bạn không cần config gì thêm để sử dụng permissions từ SSO.

**Cách 1: Sử dụng trực tiếp với permission parameter (Đơn giản nhất)**

Sử dụng middleware với permission được chỉ định trực tiếp trong route:
```php
// routes/web.php
Route::middleware(['auth', 'permission:app.dashboard'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});

Route::middleware(['auth', 'permission:app.users.list'])->group(function () {
    Route::get('/users', [UserController::class, 'index'])->name('users.index');
});
```

**Cách 2: Extend và override route permissions (Khuyến nghị cho nhiều routes)**

Tạo middleware mới trong app:
```php
// app/Http/Middleware/PermissionMiddleware.php
namespace App\Http\Middleware;

use THKHD\SsoClient\Http\Middleware\PermissionMiddleware as BasePermissionMiddleware;

class PermissionMiddleware extends BasePermissionMiddleware
{
    protected function getRoutePermissions(): array
    {
        return [
            'dashboard' => 'app.dashboard',
            'users.index' => 'app.users.list',
            'users.create' => 'app.users.create',
            // ... thêm các route khác
        ];
    }
}
```

Đăng ký middleware:
```php
// bootstrap/app.php
use App\Http\Middleware\PermissionMiddleware;

->withMiddleware(function (Middleware $middleware) {
    $middleware->alias([
        'permission' => PermissionMiddleware::class,
    ]);
})
```

Sử dụng trong routes:
```php
Route::middleware(['auth', 'permission'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/users', [UserController::class, 'index'])->name('users.index');
});

// Hoặc chỉ định permission trực tiếp
Route::middleware(['auth', 'permission:app.custom.permission'])->group(function () {
    Route::get('/custom', [CustomController::class, 'index']);
});
```

**Cách 3: Sử dụng config**

Cấu hình route-permission mapping trong `config/sso-client.php`:
```php
'route_permissions' => [
    'dashboard' => 'app.dashboard',
    'users.index' => 'app.users.list',
    'users.create' => 'app.users.create',
],
```

Sau đó sử dụng middleware trong routes:
```php
// routes/web.php
Route::middleware(['auth', 'permission'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/users', [UserController::class, 'index'])->name('users.index');
});
```

**Cách 4: Tự động sử dụng route name làm permission**

Bật auto route permission trong config:
```php
// config/sso-client.php hoặc .env
'middleware' => [
    'auto_route_permission' => true, // hoặc SSO_AUTO_ROUTE_PERMISSION=true
],
```

Với option này, route name sẽ tự động được sử dụng làm permission name:
- Route `dashboard` → check permission `dashboard`
- Route `users.index` → check permission `users.index`

**Override các method khác (nếu cần):**
```php
class PermissionMiddleware extends BasePermissionMiddleware
{
    // Override cách lấy permissions từ session
    protected function getUserPermissions(Request $request): array
    {
        // Custom logic
        return $request->session()->get('custom_permissions', []);
    }
    
    // Override cách check super admin
    protected function isSuperAdmin(Request $request): bool
    {
        // Custom logic
        return $request->user()?->is_super_admin ?? false;
    }
    
    // Override logic check permission
    protected function checkSinglePermission(array $userPermissions, string $requiredPermission): bool
    {
        // Custom permission checking logic
        return in_array($requiredPermission, $userPermissions);
    }
}
```

### 9.2. Tuỳ chỉnh bằng cách extends Base Controller
```php
use THKHD\SsoClient\Http\Controllers\BaseSSOAuthenticateController;

class CustomSSOController extends BaseSSOAuthenticateController
{
    protected function userSyncCallback(): ?callable
    {
        return function(array $userData) {
            return \App\Models\User::updateOrCreate(
                ['email' => $userData['email']],
                [
                    'name' => $userData['name'] ?? $userData['email'],
                    'phone_number' => $userData['phone_number'] ?? null,
                ]
            );
        };
    }
}
```

Sau khi extends, bạn chỉ cần cập nhật routes để sử dụng controller mới. Tất cả các method còn lại có thể override khi cần thiết nhằm phù hợp với từng ứng dụng. Apps chỉ cần `composer require thk-hd/sso-client` là có thể sử dụng đầy đủ các tính năng SSO.

## 🔐 10. Remote Logout (Force Logout từ SSO Server)

### 10.1. Mô tả
Tính năng cho phép SSO server gọi endpoint để force logout user đang đăng nhập trên client app. Hữu ích khi:
- SSO server thay đổi quyền của user
- SSO server yêu cầu bắt buộc logout (bảo mật, v.v.)
- User bị vô hiệu hóa trên SSO server

### 10.2. SSO_REMOTE_LOGOUT_SECRET là gì?

`SSO_REMOTE_LOGOUT_SECRET` là một **secret token** dùng để xác thực các request từ SSO server khi gọi endpoint remote logout. Đây là một chuỗi bí mật được chia sẻ giữa SSO server và client app.

#### Mục đích:
- **Bảo mật**: Chỉ SSO server biết secret mới có thể gọi endpoint force logout
- **Ngăn chặn**: Tránh người lạ gọi endpoint và logout user bất hợp pháp
- **Audit**: Log tất cả requests để theo dõi và audit

#### Cách hoạt động:
1. Client app cấu hình secret trong `.env`
2. SSO server gọi endpoint với secret này trong header/query/body
3. Middleware `ValidateSSOSecretMiddleware` kiểm tra secret
4. Nếu đúng → Cho phép request và logout user
5. Nếu sai → Trả về 401 Unauthorized

### 10.3. Cách tạo Secret

Secret nên là một chuỗi ngẫu nhiên, mạnh và đủ dài (khuyến nghị ít nhất 32 ký tự):

#### Cách 1: Dùng PHP
```bash
php -r "echo bin2hex(random_bytes(32));"
# Output: 4f8a9b2c3d1e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b
```

#### Cách 2: Dùng OpenSSL
```bash
openssl rand -hex 32
# Output: 3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b
```

#### Cách 3: Dùng Laravel Tinker
```bash
php artisan tinker
>>> bin2hex(random_bytes(32))
```

#### Cách 4: Online Generator
Có thể sử dụng các tool online như:
- https://www.random.org/strings/
- https://randomkeygen.com/

**Lưu ý**: Sau khi tạo secret, cần chia sẻ nó với SSO server qua kênh an toàn (không qua email, chat công khai, v.v.)

### 10.4. Cấu hình

Thêm vào `.env`:
```env
SSO_REMOTE_LOGOUT_SECRET=your-strong-secret-token-here
SSO_REMOTE_LOGOUT_ENABLED=true
```

**Ví dụ:**
```env
SSO_REMOTE_LOGOUT_SECRET=4f8a9b2c3d1e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b
SSO_REMOTE_LOGOUT_ENABLED=true
```

**Lưu ý quan trọng:**
- ✅ **Giữ bí mật**: Không commit secret vào Git, chỉ lưu trong `.env`
- ✅ **Dùng HTTPS**: Luôn sử dụng HTTPS khi truyền secret qua network
- ✅ **Chia sẻ an toàn**: Chia sẻ secret với SSO server qua kênh bảo mật
- ✅ **Rotate định kỳ**: Nên đổi secret định kỳ để tăng bảo mật (nhớ cập nhật cả SSO server)
- ⚠️ **Nếu không config**: Request sẽ được allow (backward compatibility) nhưng sẽ có warning log

### 10.5. Định nghĩa Route

```php
use THKHD\SsoClient\Http\Controllers\SSOAuthenticateController;
use THKHD\SsoClient\Http\Middleware\ValidateSSOSecretMiddleware;

// Route remote logout - được bảo vệ bởi ValidateSSOSecretMiddleware
Route::middleware([ValidateSSOSecretMiddleware::class])->group(function () {
    Route::post('remote-logout', [SSOAuthenticateController::class, 'forceLogout'])
        ->name('sso.remote-logout');
});
```

### 10.6. SSO Server gọi endpoint

**Option 1: Dùng Header**
```bash
curl -X POST https://your-app.com/remote-logout \
  -H "X-SSO-Secret: your-strong-secret-token-here" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

**Option 2: Dùng Query Parameter**
```bash
curl -X POST "https://your-app.com/remote-logout?secret=your-strong-secret-token-here" \
  -H "Content-Type: application/json" \
  -d '{"user_id": 123}'
```

**Option 3: Dùng Body**
```bash
curl -X POST https://your-app.com/remote-logout \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "secret": "your-strong-secret-token-here"
  }'
```

### 10.7. Response

**Success:**
```json
{
  "success": true,
  "message": "User logged out successfully",
  "identifier": "user@example.com"
}
```

**Error:**
```json
{
  "success": false,
  "message": "Email or user_id is required"
}
```

### 10.8. Bảo mật

#### Cơ chế bảo mật:
- **hash_equals()**: Secret token được validate bằng `hash_equals()` để chống timing attack
- **Multiple methods**: Hỗ trợ nhiều cách truyền secret:
  - Header: `X-SSO-Secret` hoặc `Authorization: Bearer <secret>`
  - Query parameter: `?secret=<secret>`
  - Body parameter: `{"secret": "<secret>"}`
- **Logging**: Tất cả requests (thành công và thất bại) đều được log để audit
- **Backward compatibility**: Nếu secret không được config, request sẽ được allow nhưng sẽ có warning log

#### Best Practices:
1. **Độ dài secret**: Tối thiểu 32 ký tự (64 ký tự hex = 32 bytes)
2. **Tính ngẫu nhiên**: Sử dụng cryptographically secure random generator
3. **Bảo mật storage**: Lưu secret trong `.env`, không commit vào Git
4. **Rotation**: Đổi secret định kỳ (ví dụ: mỗi 3-6 tháng)
5. **Monitoring**: Theo dõi logs để phát hiện các request bất thường

#### Ví dụ thực tế:

**Khi SSO server thay đổi quyền của user:**
```bash
# SSO server gọi endpoint với secret
curl -X POST https://client-app.com/remote-logout \
  -H "X-SSO-Secret: 4f8a9b2c3d1e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b" \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Client app kiểm tra secret → Đúng → Logout user ngay lập tức
```

**Khi có request không hợp lệ:**
```bash
# Request không có secret hoặc secret sai
curl -X POST https://client-app.com/remote-logout \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Response: 401 Unauthorized
# Log: "SSO remote logout request missing secret" hoặc "invalid secret"
```

## 🧭 11. Navigation Menu

### 11.1. Mô tả

Tính năng Navigation Menu cho phép client app hiển thị menu điều hướng được quản lý tập trung từ SSO server. Menu được fetch tự động từ SSO server và cache trong session, giúp:
- Quản lý menu tập trung từ SSO server
- Tự động cập nhật menu khi có thay đổi
- Hỗ trợ đa ngôn ngữ (language)
- Tự động refresh menu khi cần thiết

### 11.2. Cấu hình

Thêm vào `.env`:
```env
SSO_NAVIGATION_ENABLED=true
SSO_MENUS_URI=/api/menus
```

**Giải thích:**
- `SSO_NAVIGATION_ENABLED`: Bật/tắt tính năng navigation menu (mặc định: `true`)
  - Nếu `false`, middleware `RefreshNavigationMiddleware` sẽ bỏ qua việc fetch và refresh menu
  - Menu sẽ không được tự động fetch từ SSO server
- `SSO_MENUS_URI`: Endpoint trên SSO server để fetch menu (mặc định: `/api/menus`)

### 11.3. Đăng ký Middleware

Để tự động fetch và refresh menu, đăng ký `RefreshNavigationMiddleware`:

```php
// bootstrap/app.php
use THKHD\SsoClient\Http\Middleware\RefreshNavigationMiddleware;

->withMiddleware(function (Middleware $middleware) {
    $middleware->web([
        RefreshNavigationMiddleware::class,
    ]);
})
```

**Lưu ý:** Middleware sẽ tự động skip nếu:
- User chưa đăng nhập (guest)
- Route nằm trong `config('sso-client.middleware.skip_routes')`
- `navigation_enabled` = `false`

### 11.4. Cách sử dụng Navigation Menu

#### Cách 1: Sử dụng View Component (Khuyến nghị)

Sử dụng View Component có sẵn trong package:

```blade
{{-- resources/views/layouts/app.blade.php --}}
<!DOCTYPE html>
<html>
<head>
    <title>My App</title>
</head>
<body>
    {{-- Hiển thị navigation menu từ SSO --}}
    <x-sso::navigation-menu />
    
    <main>
        {{ $slot }}
    </main>
</body>
</html>
```

**Ưu điểm:**
- Tự động check config `navigation_enabled`
- Tự động xử lý khi menu rỗng
- Dễ sử dụng, chỉ cần một dòng code

#### Cách 2: Sử dụng trực tiếp trong View Component

Tạo View Component của riêng bạn:

```php
// app/View/Components/AppLayout.php
namespace App\View\Components;

use Illuminate\View\Component;
use THKHD\SsoClient\Services\SSOClientService;

class AppLayout extends Component
{
    public function __construct(private SSOClientService $ssoService) {}

    public function render()
    {
        $navigation = $this->ssoService->getNavigationMenu();
        
        return view('layouts.app', compact('navigation'));
    }
}
```

```blade
{{-- resources/views/layouts/app.blade.php --}}
<!DOCTYPE html>
<html>
<head>
    <title>My App</title>
</head>
<body>
    @if(config('sso-client.navigation_enabled', true) && !empty($navigation))
        {!! $navigation !!}
    @endif
    
    <main>
        {{ $slot }}
    </main>
</body>
</html>
```

#### Cách 3: Sử dụng Facade trực tiếp trong Blade

```blade
{{-- resources/views/layouts/app.blade.php --}}
@php
    $navigation = \THKHD\SsoClient\Facades\SSOClient::getNavigationMenu();
@endphp

@if(config('sso-client.navigation_enabled', true) && !empty($navigation))
    {!! $navigation !!}
@endif
```

### 11.5. Tự động lưu Menu sau khi đăng nhập

Menu sẽ được tự động fetch và lưu sau khi đăng nhập thành công nếu bạn sử dụng `SSOAuthenticateController` hoặc `BaseSSOAuthenticateController`. 

Nếu bạn tự xử lý callback, hãy gọi `storeNavigationMenu()` sau khi lấy được access token:

```php
use THKHD\SsoClient\Facades\SSOClient;

public function handleCallback(Request $request)
{
    // ... xử lý authentication ...
    
    $tokenData = SSOClient::getAccessToken($request->code);
    $accessToken = $tokenData['access_token'];
    
    // Lưu navigation menu với ngôn ngữ hiện tại
    $locale = $request->session()->get('locale', config('app.locale', 'en'));
    SSOClient::storeNavigationMenu($accessToken, $locale);
    
    // ... tiếp tục xử lý ...
}
```

### 11.6. Refresh Menu khi đổi ngôn ngữ

Khi user đổi ngôn ngữ, bạn cần refresh menu với ngôn ngữ mới:

```php
use THKHD\SsoClient\Facades\SSOClient;

public function switchLanguage(Request $request, string $language)
{
    $request->session()->put('locale', $language);
    
    // Refresh navigation menu với ngôn ngữ mới
    $accessToken = SSOClient::getSSOToken();
    if ($accessToken) {
        SSOClient::storeNavigationMenu($accessToken, $language);
    }
    
    return redirect()->back();
}
```

### 11.7. Tắt Navigation Menu

Nếu bạn không muốn sử dụng navigation menu từ SSO, có thể tắt bằng cách:

**Option 1: Tắt trong `.env`**
```env
SSO_NAVIGATION_ENABLED=false
```

**Option 2: Tắt trong config**
```php
// config/sso-client.php
'navigation_enabled' => false,
```

Khi tắt, middleware `RefreshNavigationMiddleware` sẽ bỏ qua việc fetch menu, giúp tăng hiệu suất.

### 11.8. API Endpoint trên SSO Server

SSO server cần cung cấp endpoint `/api/menus` (hoặc endpoint được config trong `SSO_MENUS_URI`) với:

**Request:**
```
GET /api/menus?lang=en&client_url=http://client-app.com
Headers:
  Authorization: Bearer {access_token}
```

**Response (Success - 200):**
```html
<nav>
    <ul>
        <li><a href="/dashboard">Dashboard</a></li>
        <li><a href="/users">Users</a></li>
        <!-- ... -->
    </ul>
</nav>
```

**Response (Forbidden - 403):**
```json
{
    "message": "User does not have permission for this client"
}
```

**Response (Unauthorized - 401):**
```json
{
    "message": "Unauthenticated"
}
```

### 11.9. Xử lý lỗi

Package tự động xử lý các trường hợp lỗi:

- **403 Forbidden**: User không có quyền truy cập client này → Tự động logout
- **401 Unauthorized**: Token không hợp lệ → Tự động logout
- **Menu rỗng**: Component sẽ trả về chuỗi rỗng, không hiển thị gì

### 11.10. Best Practices

1. **Luôn check config**: Luôn check `navigation_enabled` trước khi hiển thị menu
2. **Xử lý menu rỗng**: Luôn kiểm tra menu có rỗng không trước khi render
3. **Cache menu**: Menu được cache trong session, không cần fetch lại mỗi request
4. **Refresh khi đổi ngôn ngữ**: Nhớ refresh menu khi user đổi ngôn ngữ
5. **Error handling**: Package tự động xử lý lỗi, nhưng bạn có thể custom nếu cần