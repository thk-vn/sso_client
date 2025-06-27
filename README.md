
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
| Xử lý callback + token exchange | ✅ |
| Gọi API lấy user info | ✅ |
| Lưu session / token | ✅ |
| Hướng dẫn sử dụng | ✅ |

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
composer require thk-hd/sso-client:dev-main
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
public function login(Request $request)
{
    $state = 'sssssssssssssssssssss';
    $state = Session::get('state_sso');
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
$accessToken = SSOClient::getSSOToken();
$user = SSOClient::user($accessToken['access_token']);
```