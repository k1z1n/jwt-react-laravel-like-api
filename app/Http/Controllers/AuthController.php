<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validatedData = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $validatedData['name'],
            'email' => $validatedData['email'],
            'password' => Hash::make($validatedData['password']),
        ]);

        return $this->respondWithTokens($user);
    }

    // Авторизация пользователя
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $credentials['email'])->first();

        if (!$user) {
            return response()->json(['message' => 'Пользователь не найден'], 404);
        }

        if ($user->status === 'blocked') {
            return response()->json(['message' => 'Ваш аккаунт заблокирован. Обратитесь к администратору.'], 403);
        }

        if (!$token = JWTAuth::attempt($credentials)) {
            return response()->json(['message' => 'Неверные учетные данные'], 401);
        }

        return $this->respondWithTokens($user, $token);
    }


    public function user(Request $request)
    {
        $cuci = $request->hasCookie('access_token');
        $cuci2 = $request->hasCookie('refresh_token');
        \Log::info(auth()->user());
        return response()->json(['user' => auth()->user(), 'access' => $cuci, 'refresh' => $cuci2]);
    }

    public function checkCookie(Request $request)
    {
        $access = $request->cookie('access_token');
        $refresh = $request->cookie('refresh_token');
        return response()->json(['access_token' => $access, 'refresh_token' => $refresh]);
    }


    // Обновление токенов
    public function refresh(Request $request)
    {
        $refreshToken = $request->cookie('refresh_token');

        if (!$refreshToken) {
            return response()->json(['message' => 'Отсутствует токен обновления'], 401)
                ->cookie('access_token', '', -1, '/', null, true, true, false, 'None')
                ->cookie('refresh_token', '', -1, '/', null, true, true, false, 'None');
        }

        try {
            $payload = JWTAuth::setToken($refreshToken)->getPayload();

            if ($payload->get('type') !== 'refresh') {
                return response()->json(['message' => 'Неверный тип токена'], 401)
                    ->cookie('access_token', '', -1, '/', null, true, true, false, 'None')
                    ->cookie('refresh_token', '', -1, '/', null, true, true, false, 'None');
            }

            $user = JWTAuth::setToken($refreshToken)->toUser();

            return $this->respondWithTokens($user);
        } catch (\Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['message' => 'Токен обновления истек'], 401)
                ->cookie('access_token', '', -1, '/', null, true, true, false, 'None')
                ->cookie('refresh_token', '', -1, '/', null, true, true, false, 'None');
        } catch (\Exception $e) {
            return response()->json(['message' => 'Недействительный токен обновления'], 401)
                ->cookie('access_token', '', -1, '/', null, true, true, false, 'None')
                ->cookie('refresh_token', '', -1, '/', null, true, true, false, 'None');
        }
    }


    // Выход из системы
    public function logout()
    {
        try {
            $accessToken = JWTAuth::getToken();
            if ($accessToken) {
                JWTAuth::invalidate($accessToken);
            }

            $refreshToken = request()->cookie('refresh_token');
            if ($refreshToken) {
                JWTAuth::setToken($refreshToken)->invalidate();
            }
        } catch (\Exception $e) {
            // Обработка ошибок, если необходимо
        }

        return response()->json(['message' => 'Успешный выход'])
            ->cookie('access_token', '', -1, '/', null, true, true, false, 'None')
            ->cookie('refresh_token', '', -1, '/', null, true, true, false, 'None');
    }


    // Формирование ответа с токенами
    private function respondWithTokens($user, $accessToken = null)
    {
        $accessTokenTTL = env('JWT_TTL'); // Время жизни access токена в минутах
        $refreshTokenTTL = env('JWT_REFRESH_TTL'); // Время жизни refresh токена в минутах (30 дней)

        // Создаем access токен с индивидуальным временем жизни
        $accessToken = $accessToken ?? JWTAuth::customClaims([
            'exp' => now()->addMinutes($accessTokenTTL)->timestamp,
            'type' => 'access'
        ])->fromUser($user);

        // Создаем refresh токен с индивидуальным временем жизни и типом
        $refreshToken = JWTAuth::customClaims([
            'exp' => now()->addMinutes($refreshTokenTTL)->timestamp,
            'type' => 'refresh'
        ])->fromUser($user);

        return response()->json(['user' => $user])
            ->cookie('access_token', $accessToken, $accessTokenTTL, '/', null, true, true, false, 'None')
            ->cookie('refresh_token', $refreshToken, $refreshTokenTTL, '/', null, true, true, false, 'None');
    }

}
