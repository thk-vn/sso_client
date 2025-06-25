
# 📄 Package Laravel xác thực OAuth2 (SSO Client)

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
| Redirect login | ✅ |
| Xử lý callback + token exchange | ✅ |
| Gọi API lấy user info | ✅ |
| Lưu session / token | ✅ |
| Hướng dẫn sử dụng | ✅ |
| Logout (SSO + local) | X |
| Middleware bảo vệ route | X |

## ⚙️ 2. Kỹ thuật sử dụng

- **Chuẩn xác thực**: OAuth2 Authorization Code Flow.
- **Laravel version**: Tương thích Laravel 9 trở lên.
- **Công nghệ chính**:
  - Laravel Service Provider.
  - Middleware.
  - Laravel HTTP Client.
  - Session hoặc Cache.
  - Config publish.

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
│   ├── Http/
│   │   ├── Controllers/
│   │   │   ├── AuthController.php
│   │   └── Middleware/
│   │       └── EnsureSSOAuthenticated.php
│   ├── Services/
│   │   └── TokenService.php
│   ├── Facades/
│   │   └── SSOClient.php
│   └── SSOClientManager.php
├── routes/
│   └── web.php
├── config/
│   └── sso-client.php
├── README.md
├── composer.json
```

## ⚙️ 6. Các thành phần kỹ thuật cụ thể

### 6.1. Cấu hình (`config/sso-client.php`)
```php
return [
    'client_id' => env('SSO_CLIENT_ID'),
    'client_secret' => env('SSO_CLIENT_SECRET'),
    'redirect_uri' => env('SSO_REDIRECT_URI'),
    'server_url' => env('SSO_SERVER_URL'),
];
```

### 6.2. Middleware - Chưa phát triển
```php
public function handle($request, Closure $next)
{
    if (!session()->has('sso_user')) {
        return redirect()->route('sso.login');
    }

    return $next($request);
}
```

### 6.3. Controller flow
- `redirectToSSO()`: Redirect đến Authorization Server.
- `handleCallback()`: Đổi `code` thành `access_token`, lưu thông tin user.
- `logout()`: Client app tự xử lí logout.

## 📘 7. Cách sử dụng package (ví dụ)

### A. Cài đặt
```bash
composer require thk-hd/sso-client
php artisan vendor:publish --tag=sso-client-config
```

### B. Cấu hình `.env`
```env
SSO_SERVER_URL=http://127.0.0.1:8001
SSO_CLIENT_ID=xxxxxxxxxxxxxxxxxx
SSO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxx
SSO_REDIRECT_URI=http://localhost:8000/sso-client/callback
```

### C. Sử dụng Middleware
```php
Route::middleware(['web', 'sso.auth'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
```

### D. Gọi thông tin người dùng - Chưa phát triển
```php
$user = SSOClient::user(); // trả về array hoặc model từ session
```

# 🧩 Hướng dẫn cấu hình `resolve` route để xử lý đăng nhập từ SSO

Sau khi SSO Server xác thực thành công, nó sẽ chuyển hướng về route `resolve` trong app client, kèm theo thông tin người dùng được mã hoá. Bạn có thể tuỳ chỉnh cơ chế login theo ý muốn, dưới đây là mẩu xử lí tham khảo:

## 📄 8. Controller, Routes, Config cần xử lý

```php
<form method="POST" action="{{ route('sso-client.login') }}">
    @csrf
    <div class="form-group">
        <x-button color="primary" size="lg" class="btn-block" type="submit">
            {{ __('messages.button.login') }} </x-button>
    </div>
</form>
```

```php
/*
|--------------------------------------------------------------------------
| User Resolver Route
|--------------------------------------------------------------------------
|
| Route name trỏ đến controller xử lý đăng nhập user từ thông tin SSO.
|
*/
'user_resolver' => 'sso-client.user-resolver',
```

```php
use App\Http\Controllers\SSOLoginController;

Route::get('/sso/resolve', [SSOLoginController::class, 'resolve'])
    ->name('sso-client.user-resolver')
    ->middleware('signed');
```

```php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;

class SSOLoginController extends Controller
{
    /**
     * Resolve
     *
     * Xử lý dữ liệu từ SSO server và thực hiện đăng nhập user.
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function resolve(Request $request)
    {
        $userInfo = decrypt($request->query('data'));

        $user = User::where('email', $userInfo['email'])->first();

        if (! $user) {
            abort(403, 'Tài khoản chưa được cấp phép để đăng nhập.');
        }

        Auth::login($user);

        return redirect()->intended('/');
    }
}
```

## 📌 9. Mở rộng sau này

- Hỗ trợ refresh token tự động.
- Caching thông tin user.
- Tự động attach access token khi gọi API nội bộ.

## 🧠 10. Kết luận

Việc đóng gói hệ thống OAuth2 client thành một Laravel package là bước quan trọng để **chuẩn hóa và tái sử dụng** quá trình xác thực giữa nhiều hệ thống Laravel. Điều này giúp giảm chi phí bảo trì, tăng tốc độ phát triển và đảm bảo tính bảo mật cho toàn bộ hệ sinh thái ứng dụng nội bộ.