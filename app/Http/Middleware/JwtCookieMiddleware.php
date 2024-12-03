<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Cookie;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JwtCookieMiddleware
{
    public function handle($request, Closure $next)
    {
        try {
            if ($request->cookie('access_token')) {
                $token = $request->cookie('access_token');
                JWTAuth::setToken($token);
                $user = JWTAuth::authenticate();
                \Log::info('Queued Cookies: ', Cookie::getQueuedCookies());
                $request->setUserResolver(function () use ($user) {
                    return $user;
                });
            } else {
                return response()->json(['message' => 'Токен не предоставлен'], 401)->cookie('access_token', '', 0, '/', null, true, true, false, 'None')
                    ->cookie('refresh_token', '', 0, '/', null, true, true, false, 'None');
            }
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['message' => 'Токен истек'], 401)->cookie('access_token', '', 0, '/', null, true, true, false, 'None')
                ->cookie('refresh_token', '', 0, '/', null, true, true, false, 'None');
        } catch (\Exception $e) {
            return response()->json(['message' => 'Недействительный токен'], 401)->cookie('access_token', '', 0, '/', null, true, true, false, 'None')
                ->cookie('refresh_token', '', 0, '/', null, true, true, false, 'None');
        }

        return $next($request);
    }
}
