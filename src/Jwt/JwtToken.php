<?php

declare(strict_types=1);

namespace Gzqsts\Qstapp\Jwt;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Gzqsts\Qstapp\Exception\JwtTokenException;
use Gzqsts\Qstapp\Exception\JwtLoginTokenException;
use Gzqsts\Qstapp\Exception\JwtQuitLoginTokenException;
use UnexpectedValueException;
use Shopwwi\LaravelCache\Cache;
use support\Db;

class JwtToken
{
    /**
     * access_token.
     */
    private const ACCESS_TOKEN = 1;

    /**
     * refresh_token.
     */
    private const REFRESH_TOKEN = 2;

    /**
     * @desc: 生成令牌
     * @param array $extend
     * @return array
     * @throws JwtTokenException
     */
    public static function generateToken(array $extend): array
    {
        if (!isset($extend['id'])) {
            throw new JwtTokenException(trans('jwt.lackId',[], 'gzqsts'));
        }
        $config = self::_getConfig();
        $CacheKey = $config['cache_token_pre'] . $extend['id'];
        $res = Cache::rememberForever($CacheKey, function () use ($extend, $CacheKey){
            $res = Db::table('qst_user_token')
                ->where('expires_in','>', time())
                ->where('uid', $extend['id'])->first();
            $res = json_decode(json_encode($res), true);
            if($res){
                Cache::forever($CacheKey, $res);
            }
            return $res;
        });
        if($res && time() < ($res['expires_in'] - $config['leeway'])){
            //没有开启单点 单设备登录
            if(!$config['is_single_device']){
                return $res;
            }
            if($res['ip'] == request()->getRealIp()){
                return $res;
            }
        }
        $config['access_exp'] = $extend['access_exp'] ?? $config['access_exp'];
        $config['refresh_exp'] = $extend['refresh_exp'] ?? $config['refresh_exp'];
        $extend['ip'] = request()->getRealIp();
        if(!isset($extend['tokenType'])){
            $extend['tokenType'] = 'user';
        }
        $payload = self::generatePayload($config, $extend);
        $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
        $token = [
            'ip' => $extend['ip'],
            'expires_in' => time() + $config['access_exp'],
            'access_token' => self::makeToken($payload['accessPayload'], self::getPrivateKey($config), $config['algorithms']),
            'refresh_token' => self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']),
            'created_at' => date('Y-m-d H:i:s')
        ];
        return self::upDataToken($token, ['uid' => $extend['id'], 'type' => $extend['tokenType']]);
    }

    /**
     * @desc: 刷新令牌 - 同时刷新绑定字段
     *
     * @param string $refreshToken
     * @param array $upExtend
     * @return array|string[]
     */
    public static function refreshToken(string $refreshToken = '', array $upExtend = []): array
    {
        $refreshToken = $refreshToken ?? request()->header('X-Qst-Refresh-Token');
        if(empty($refreshToken) || 'undefined' == $refreshToken){
            //刷新令牌无效
            throw new JwtTokenException(trans('jwt.token_invalid',[], 'gzqsts'));
        }
        $config = self::_getConfig();
        //返回刷新令牌加密信息
        $refreshData = self::verifyToken($refreshToken, self::REFRESH_TOKEN);
        if (!isset($refreshData['extend']['id'])) {
            throw new JwtTokenException(trans('jwt.lackId',[], 'gzqsts'));
        }
        $refreshData['extend']['ip'] = request()->getRealIp();
        if(!empty($upExtend)){
            $refreshData['extend'] = array_merge($refreshData['extend'], $upExtend);
        }
        $payload = self::generatePayload($config, $refreshData['extend']);
        //修改新令牌有效时间
        $refreshData['exp'] = time() + $config['access_exp'];
        //创建新令牌
        $new_access_token = self::makeToken($refreshData, self::getPrivateKey($config), $config['algorithms']);
        $refreshSecretKey = self::getPrivateKey($config, self::REFRESH_TOKEN);
        //修改刷新令牌有效时间
        $payload['refreshPayload']['exp'] = time() + $config['refresh_exp'];
        $new_refresh_token = self::makeToken($payload['refreshPayload'], $refreshSecretKey, $config['algorithms']);
        $newList = [
            'ip' => $refreshData['extend']['ip'],
            'expires_in' => $refreshData['exp'],
            'access_token' => $new_access_token,
            'refresh_token' => $new_refresh_token,
            'created_at' => date('Y-m-d H:i:s')
        ];
        return self::upDataToken($newList, ['uid' => $refreshData['extend']['id'], 'type' => $refreshData['extend']['tokenType']]);
    }

    /**
     * @desc: 更新token数据缓存
     * @param array $newToekns
     * @param array $where
     * @return array
     */
    private static function upDataToken(array $newToekns = [], array $where = []): array
    {
        $config = self::_getConfig();
        Db::table('qst_user_token')
            ->updateOrInsert(
                $where,
                $newToekns
            );
        $newToekns = array_merge($newToekns, $where);
        Cache::forever($config['cache_token_pre'] . $where['uid'], $newToekns);
        return $newToekns;
    }

    /**
     * @desc: 校验令牌
     * @param string $token
     * @param int $tokenType
     * @return array
     */
    private static function verifyToken(string $token, int $tokenType): array
    {
        $config = self::_getConfig();
        $publicKey = self::ACCESS_TOKEN == $tokenType ? self::getPublicKey($config['algorithms']) : self::getPublicKey($config['algorithms'], self::REFRESH_TOKEN);
        JWT::$leeway = $config['leeway'];
        try {
            $decoded = JWT::decode($token, new Key($publicKey, $config['algorithms']));
        } catch (SignatureInvalidException $signatureInvalidException) {
            //身份验证令牌无效
            throw new JwtTokenException(trans('jwt.token_invalid',[], 'gzqsts'));
        } catch (BeforeValidException $beforeValidException) {
            //身份验证令牌尚未生效
            throw new JwtTokenException(trans('jwt.token_check_invalid',[], 'gzqsts'));
        } catch (ExpiredException $expiredException) {
            //身份验证会话已过期，请重新登录！
            throw new JwtLoginTokenException(trans('jwt.token_to_login',[], 'gzqsts'));
        } catch (UnexpectedValueException $unexpectedValueException) {
            //获取的扩展字段不存在
            throw new JwtTokenException(trans('jwt.token_Field_not_exist',[], 'gzqsts'));
        } catch (\Exception $exception) {
            throw new JwtTokenException($exception->getMessage());
        }
        $decodeToken = json_decode(json_encode($decoded), true);
        if ($config['is_single_device'] && $decodeToken['extend']['ip'] != request()->getRealIp()) {
           //验证IP是否一致不一致 已在别的地方登录强制下线
            throw new JwtQuitLoginTokenException(trans('jwt.token_log_off',[], 'gzqsts'));
        }
        return $decodeToken;
    }

    /**
     * @desc: 验证令牌
     * @param int $tokenType
     * @param string|null $token
     * @return array
     */
    public static function verify(int $tokenType = self::ACCESS_TOKEN, string $token = ''): array
    {
        if(!$token){
            $token = request()->header('X-Qst-Token');
            if($tokenType == 2){
                $token = request()->header('X-Qst-Refresh-Token');
            }
        }
        if(empty($token) || 'undefined' == $token){
            //刷新令牌无效
            throw new JwtTokenException(trans('jwt.token_invalid',[], 'gzqsts'));
        }
        return self::verifyToken($token, $tokenType);
    }

    /**
     * @desc: 注销令牌 全部或 指定用户 或 指定用户及指定类型
     * @param array $param
     * @return bool
     */
    public static function clear(array $param = []): bool
    {
        $uid = $param['uid']??'';
        $type = $param['type']??'';
        $config = self::_getConfig();
        Db::table('qst_user_token')
            ->when($uid, function ($query, $uid) {
                return $query->where('uid', $uid);
            })
            ->when($type, function ($query, $type) {
                return $query->where('type', $type);
            })
            ->sharedLock()
            ->orderBy('uid')
            ->lazy()
            ->each(function ($val) use ($uid, $type, $config){
                Db::table('qst_user_token')
                    ->when($uid, function ($query, $uid) {
                        return $query->where('uid', $uid);
                    })
                    ->when($type, function ($query, $type) {
                        return $query->where('type', $type);
                    })
                    ->delete();
                Cache::forget($config['cache_token_pre'] . $val->uid);
            });
        return true;
    }

    /**
     * @desc: 获取当前登录ID
     * @throws JwtTokenException
     * @return mixed
     */
    public static function getCurrentId()
    {
        return self::getExtendVal('id') ?? 0;
    }

    /**
     * @desc: 获取指定令牌扩展内容字段的值
     *
     * @param string $val
     * @return mixed|string
     * @throws JwtTokenException
     */
    public static function getExtendVal(string $val)
    {
        return self::getTokenExtend()[$val] ?? '';
    }

    /**
     * @desc: 获取扩展字段.
     * @return array
     * @throws JwtTokenException
     */
    public static function getTokenExtend(): array
    {
        return (array) self::verify()['extend'];
    }

    /**
     * @desc: 获令牌有效期剩余时长.
     * @param int $tokenType
     * @return int
     */
    public static function getTokenExp(int $tokenType = self::ACCESS_TOKEN): int
    {
        return (int) self::verify($tokenType)['exp'] - time();
    }

    /**
     * @desc: 生成令牌.
     *
     * @param array  $payload    载荷信息
     * @param string $secretKey  签名key
     * @param string $algorithms 算法
     * @return string
     */
    private static function makeToken(array $payload, string $secretKey, string $algorithms): string
    {
        return JWT::encode($payload, $secretKey, $algorithms);
    }

    /**
     * @desc: 获取加密载体.
     *
     * @param array $config 配置文件
     * @param array $extend 扩展加密字段
     * @return array
     */
    private static function generatePayload(array $config, array $extend): array
    {
        $basePayload = [
            'iss' => $config['iss'],
            'iat' => time(),
            'exp' => time() + $config['access_exp'],
            'extend' => $extend
        ];
        $resPayLoad = [];
        $resPayLoad['accessPayload'] = $basePayload;
        $basePayload['exp'] = time() + $config['refresh_exp'];
        $resPayLoad['refreshPayload'] = $basePayload;
        return $resPayLoad;
    }

    /**
     * @desc: 根据签名算法获取【公钥】签名值
     * @param string $algorithm 算法
     * @param int $tokenType 类型
     * @return string
     * @throws JwtTokenException
     */
    private static function getPublicKey(string $algorithm, int $tokenType = self::ACCESS_TOKEN): string
    {
        $config = self::_getConfig();
        switch ($algorithm) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_public_key'] : $config['refresh_public_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }
        return $key;
    }

    /**
     * @desc: 根据签名算法获取【私钥】签名值
     * @param array $config 配置文件
     * @param int $tokenType 令牌类型
     * @return string
     */
    private static function getPrivateKey(array $config, int $tokenType = self::ACCESS_TOKEN): string
    {
        switch ($config['algorithms']) {
            case 'HS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_secret_key'] : $config['refresh_secret_key'];
                break;
            case 'RS512':
            case 'RS256':
                $key = self::ACCESS_TOKEN == $tokenType ? $config['access_private_key'] : $config['refresh_private_key'];
                break;
            default:
                $key = $config['access_secret_key'];
        }
        return $key;
    }

    /**
     * @desc: 获取配置文件
     * @return array
     * @throws JwtTokenException
     */
    private static function _getConfig(): array
    {
        $config = config('plugin.gzqsts.qstapp.app.jwt');
        if (empty($config)) {
            throw new JwtTokenException(trans('jwt.notConfig',[], 'gzqsts'));
        }
        return $config;
    }
}
