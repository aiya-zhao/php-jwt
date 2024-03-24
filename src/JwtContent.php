<?php

namespace AiyaZhao\Jwt;

use Exception;

// 自定义jwt
class JwtContent{
    // 签名算法
    private $alg = 'sha256';

    // 令牌的类型
    private $typ = 'JWT';

    // 签发人
    private $iss;

    // 主题
    public $sub;

    // 受众
    private $aud;

    // 过期时间
    private $exp;

    // 生效时间，在此之前是无效的
    private $nbf;

    // 签发时间
    private $iat;

    // 编号
    private $jti;

    // 自定义字段
    private Array $foo;

    // 过期时间 单位：分钟
    private $ttl = 120;

    // 过期刷新时间 单位：分钟
    private $refresh_ttl = 240;

    // 头部数据
    private $head;

    // 头部数组
    public $head_arr;

    // 载体
    private $body;

    // 载体数组
    public $body_arr;

    // 签名
    private $sign;

    // token
    public $token;

    // jwt秘钥
    private $jwt_secret;

    // 生成头部
    public function __construct($config){
        $this->jwt_secret = $config['jwt_secret'] ?? '';
        $this->ttl = $config['ttl'] ?? $this->ttl;
        $this->refresh_ttl = $config['refresh_ttl'] ?? $this->refresh_ttl;
        $this->alg = strtoupper($config['alg'] ?? $this->alg);
    }

    // 设置过期时间
    public function setTtl($m = 0){
        $this->ttl = $m;
        return $this;
    }

    // 获取过期时间
    public function getTtl(){
        return $this->ttl;
    }

    // 设置刷新时间
    public function setRefreshTtl($m = 0){
        $this->refresh_ttl = $m;
        return $this;
    }

    // 获取刷新时间
    public function getRefreshTtl(){
        return $this->refresh_ttl;
    }

    // 设置主题
    public function setSub($m = ''){
        $this->sub = $m;
        return $this;
    }

    // 获取主题
    public function getSub(){
        return $this->sub;
    }

    // 设置受众
    public function setAud($m = ''){
        $this->aud = $m;
        return $this;
    }

    // 获取受众
    public function getAud(){
        return $this->aud;
    }

    // 设置自定义字段
    public function setFoo(Array $m = []){
        $this->foo = $m;
        return $this;
    }

    // 获取自定义字段
    public function getFoo(){
        return $this->foo;
    }

    // 生成jwt头
    protected function setHead(){
        $this->head_arr = [
            'alg' => strtoupper($this->alg),
            'typ' => $this->typ,
        ];
        $this->head = $this->base64urlEncode(json_encode($this->head_arr));
    }

    // 获取jwt头
    public function getHead(){
        return $this->head_arr;
    }

    // 生成jwt载荷
    protected function setBody(){
        $this->iat = time();
        $this->body_arr = [
            'iat' => $this->iat
        ];
        if($this->ttl > 0){
            $this->body_arr['exp'] = $this->iat + $this->ttl * 60;
        }

        if($this->sub){
            $this->body_arr['sub'] = $this->sub;
        }

        if($this->aud){
            $this->body_arr['aud'] = $this->aud;
        }
        
        if($this->foo){
            $this->body_arr['foo'] = $this->foo;
        }

        $this->body = $this->base64urlEncode(json_encode($this->body_arr));
    }

    // 获取jwt载荷
    public function getBody(){
        return $this->body_arr;
    }
    
    // 设置签名
    protected function setSign(){
        $this->setHead();
        $this->setBody();
        $this->sign = $this->base64urlEncode(hash_hmac(strtolower($this->alg), $this->head . '.' . $this->body, $this->jwt_secret));
    }

    // 验证签名
    protected function checkSign(){
        $sign = $this->base64urlEncode(hash_hmac(strtolower($this->alg), $this->head . '.' . $this->body, $this->jwt_secret));
        if($sign != $this->sign){
            throw new Exception('token签名错误', 404);
        }
    }

    // 设置token
    protected function setToken(){
        $this->setSign();
        $this->token = $this->head . '.' . $this->body . '.' . $this->sign;
    }

    // 重置token
    protected function resetToken(){
        $this->setToken();
        return $this->token;
    }

    // 生成jwt
    public function getToken(){
        if($this->token){
            return $this->token;
        }
        return $this->resetToken();
    }

    // 解析token
    public function parseToekn($token = null){
        $this->token = $token;
        $arr = explode('.', $token);
        $this->head = $arr[0] ?? '';
        $this->head_arr = json_decode(base64_decode($this->head), true);
        $this->alg = $this->head_arr['alg'] ?? $this->alg;
        $this->body = $arr[1] ?? '';
        $this->body_arr = json_decode(base64_decode($this->body), true);
        $this->exp = $this->body_arr['exp'] ?? 0;
        $this->sub = $this->body_arr['sub'] ?? '';
        $this->sign = $arr[2] ?? '';
        $this->checkSign();
        return $this;
    }

    // 验证token有效期
    public function checkToken($token = ''){
        if($token){
            $this->parseToekn($token);
        }
        // 验证token有效期
        if($this->exp && $this->exp < time()){
            throw new Exception('token过期', 403);
        }
        return $this;
    }

    // 刷新token
    public function refreshToken($token = ''){
        if($token){
            $this->parseToekn($token);
        }        
        $this->canRefresh();
        $this->sub = $this->body_arr['sub'] ?? '';
        $this->aud = $this->body_arr['aud'] ?? '';
        return $this->resetToken();
    }

    // 是否能刷新token
    private function canRefresh(){
        if(!$this->token){
            throw new Exception('token不存在', 403);
        }
        // 验证token能否刷新
        if($this->exp && $this->exp < (time() - $this->refresh_ttl * 60)){
            throw new Exception('token刷新期已过', 403);
        }
    }

    // 生成base64
    protected function base64urlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    // 直接输出对象
    public function __toString(){
        return $this->token ? $this->token : '';
    }
}

