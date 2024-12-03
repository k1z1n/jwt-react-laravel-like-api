<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;

Route::group(['middleware' => 'api'], function ($router) {
    Route::post('register', [AuthController::class, 'register']);
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('/check-cookie', [AuthController::class, 'checkCookie']);
    // Применение middleware к защищенным маршрутам
    Route::middleware('jwt.cookie')->group(function () {
        Route::post('/user',[AuthController::class, 'user']);
    });
});
