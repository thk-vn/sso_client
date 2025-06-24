
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
| 6 | Client dùng `access_token` để gọi API `/userinfo` hoặc `/me` |
| 7 | Client lưu thông tin user vào session hoặc cache |

## 📦 4. Tính năng chính của Package

| Chức năng | Mô tả |
|-----------|-------|
| `Login Redirect` | Hàm xử lý chuyển hướng người dùng tới SSO |
| `Callback Handler` | Hàm nhận `code`, đổi sang `access_token`, lấy thông tin người dùng |
| `Token Service` | Lưu token, xử lý refresh token (nếu cần) |
| `Get User` | Lấy thông tin người dùng từ token |
| `Middleware` | Bảo vệ route yêu cầu đăng nhập |
| `Logout` | Xoá session, token, gọi logout URL của SSO |

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
    'auth_endpoint' => env('SSO_AUTH_ENDPOINT'),
    'token_endpoint' => env('SSO_TOKEN_ENDPOINT'),
    'user_info_endpoint' => env('SSO_USER_INFO_ENDPOINT'),
    'logout_endpoint' => env('SSO_LOGOUT_ENDPOINT'),
];
```

### 6.2. Middleware
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
- `logout()`: Gọi logout SSO, xoá session local.

## 📘 7. Cách sử dụng package (ví dụ)

### A. Cài đặt
```bash
composer require thk-hd/sso-client
php artisan vendor:publish --tag=sso-client-config
```

### B. Cấu hình `.env`
```env
SSO_CLIENT_ID=my-client-id
SSO_CLIENT_SECRET=my-secret
SSO_REDIRECT_URI=https://my-app.com/sso/callback
SSO_AUTH_ENDPOINT=https://sso-server.com/oauth/authorize
SSO_TOKEN_ENDPOINT=https://sso-server.com/oauth/token
SSO_USER_INFO_ENDPOINT=https://sso-server.com/api/user
SSO_LOGOUT_ENDPOINT=https://sso-server.com/logout
```

### C. Sử dụng Middleware
```php
Route::middleware(['web', 'sso.auth'])->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
```

### D. Gọi thông tin người dùng
```php
$user = SSOClient::user(); // trả về array hoặc model từ session
```

## ✅ 8. Checklist chức năng hoàn chỉnh

| Tính năng | Trạng thái |
|-----------|------------|
| Cấu trúc package Laravel chuẩn | X |
| Config publish được |X |
| Redirect login | X |
| Xử lý callback + token exchange | X |
| Middleware bảo vệ route | X |
| Gọi API lấy user info | X |
| Lưu session / token | X |
| Logout (SSO + local) | X |
| Hướng dẫn sử dụng | ✅ |

## 📌 9. Mở rộng sau này

- Hỗ trợ refresh token tự động.
- Caching thông tin user.
- Tự động attach access token khi gọi API nội bộ.

## 🧠 10. Kết luận

Việc đóng gói hệ thống OAuth2 client thành một Laravel package là bước quan trọng để **chuẩn hóa và tái sử dụng** quá trình xác thực giữa nhiều hệ thống Laravel. Điều này giúp giảm chi phí bảo trì, tăng tốc độ phát triển và đảm bảo tính bảo mật cho toàn bộ hệ sinh thái ứng dụng nội bộ.