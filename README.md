## 要求
- PHP >= 7.4
## 安装
~~~ composer
composer require aiya-zhao/php-jwt
~~~
## 用法
~~~ php
use AiyaZhao\Jwt\JWT;

// 前端接口token验证配置
$config_api = [
    'jwt_secret'     => 'abc',    // 秘钥
    'ttl'            => 60 * 2,   // 过期时间 分钟
    'refresh_ttl'    => 60 * 4,   // 刷新时间 分钟
    'alg'            => 'sha256'  // 签名算法
];

// 后台接口token验证配置
$config_admin = [
    'jwt_secret'     => 'bcd',
    'ttl'            => 60 * 24 * 2,
    'refresh_ttl'    => 60 * 24 * 4,
    'alg'            => 'sha256'
];

$token_api = JWT::config($config_api)->setSub(123)->getToken();  // 获取token
echo $token;  // 输出token
$head_arr = JWT::getHead();  // 获取头信息
$body_arr = JWT::getBody();  // 获取载荷信息
$jwt = JWT::parseToekn($token);   // 解析token信息
$head_arr = $jwt->getHead(); // 获取解析token的头信息
$check_token = JWT::checkToken($token); // 验证token有效期
$token_admin = "xxx.xxx.xxx"; // 后台token
$jwt_admin = JWT::config($config_admin)->parseToekn($token_admin);   // 解析后台接口token信息
$head_arr_admin = JWT::getHead();  // 获取头信息
$refresh_token = JWT::refreshToken();  // 刷新token
echo $refresh_token;  // 输出刷新后的token
$sub = JWT::getSub();  // 获取主题
~~~
