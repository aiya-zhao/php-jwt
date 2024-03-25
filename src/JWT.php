<?php

namespace AiyaZhao\Jwt;

use Exception;
use AiyaZhao\Jwt\JwtContent;

/**
 * Class JWT
 * @package AiyaZhao\Jwt;
 *
 * @method static setTtl($ttl) 设置过期时间 单位：分钟
 * @method static getTtl() 获取过期时间
 * @method static setRefreshTtl($refresh_ttl) 设置刷新时间 单位：分钟
 * @method static getRefreshTtl() 获取刷新时间
 * @method static setSub($sub) 设置主题
 * @method static getSub() 获取主题
 * @method static setAud($aud) 设置受众
 * @method static getAud() 获取受众
 * @method static setFoo(Array $foo) 设置自定义字段
 * @method static setFoofoo() 获取自定义字段
 * @method static getHead() 获取jwt头
 * @method static getBody() 获取jwt载荷
 * @method static getToken() 生成jwt
 * @method static parseToekn($token) 解析token
 * @method static checkToken($token | null) 验证token有效期
 * @method static refreshToken($token | null) 刷新token
 */
class JWT
{
    /**
     * eg:$config = [
     *      'jwt_secret'     => '123',         // 秘钥
     *      'ttl'            => 60 * 24 * 15,  // 过期时间 分钟
     *      'refresh_ttl'    => 60 * 24 * 30,  // 刷新时间 分钟
     *      'alg'            => 'sha256'       // 签名算法
     *   ]
     */
    public static Array $config = [];
    
    // jwt_content单例
    private static $jwt_content = null;

    /**
     * @param Array $config
     * @return JwtContent
     */
    public static function config(Array $config) {
        if(static::$config == $config && !empty($config) && static::$jwt_content){
            return static::$jwt_content;
        }
        static::$config = $config;
        if (empty($config)) {
            throw new Exception("jwt配置不存在");
        }
        static::$jwt_content = new JwtContent($config);
        return static::$jwt_content;
    }

    /**
     * @param $name
     * @param $arguments
     * @return mixed
     */
    public static function __callStatic($name, $arguments)
    {
        return static::config(static::$config)->{$name}(... $arguments);
    }
}
