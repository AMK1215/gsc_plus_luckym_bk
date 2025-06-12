<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\V1\Dashboard\AuthController;
use App\Http\Controllers\Api\V1\Dashboard\Agent\AgentController;
use App\Http\Controllers\Api\V1\Dashboard\Agent\AgentUtilityController;
use App\Http\Controllers\Api\V1\Dashboard\DashboardController;
/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "api" middleware group. Make something great!
|
*/

// Group ALL API routes that should have CORS applied and are part of your API
Route::middleware('api')->group(function () {

    // User details route (protected by Sanctum, and also benefits from CORS)
    // Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    //     return $request->user();
    // });

    // Dashboard Authentication Routes (Login/Logout)
    // These need CORS to work, so they are explicitly inside the 'api' group.
    Route::prefix('dashboardauth')->group(function () {
        Route::post('/login', [AuthController::class, 'login']);
        Route::post('/logout', [AuthController::class, 'logout']); // Logout also needs CORS if it's an API call
    });

    // All authenticated Dashboard Routes
    // This group uses 'auth:sanctum' middleware, which now runs *after* CORS
    Route::group(['middleware' => ['auth:sanctum']], function () {
        Route::prefix('dashboard')->group(function () {
            Route::get('/admin', [DashboardController::class, 'index']);
            Route::get('/user', [AuthController::class, 'getUser']);
            Route::post('/admin/change-password', [AuthController::class, 'changePassword']);
            Route::prefix('agent')->group(function () {
                Route::get('/get-agent-list', [AgentController::class, 'index']);
                Route::get('/generate-username', [AgentUtilityController::class, 'generateRandomString']);
                Route::get('/generate-referral-code', [AgentUtilityController::class, 'generateReferralCode']);
                Route::get('/payment-types', [AgentUtilityController::class, 'getPaymentTypes']);
                Route::post('/agent-create', [AgentController::class, 'store']);
                Route::post('/agent-cash-in/{id}', [AgentController::class, 'makeCashIn']);
                Route::post('/agent-cash-out/{id}', [AgentController::class, 'makeCashOut']);
                Route::get('/get-admin-balance', [AgentController::class, 'getAdminBalance']);
                Route::post('/agent-change-password/{id}', [AgentController::class, 'makeChangePassword']);
                Route::post('/agent-ban/{id}', [AgentController::class, 'banAgent']);
                Route::post('/agent-update/{id}', [AgentController::class, 'update']);
            });
        });
    });

}); // End of the main 'api' middleware group

// The commented-out sections are fine to remain commented or be removed
// Route::prefix('dashboardlogin/agent-utilities')->group(function () { /* ... */ });
// Route::prefix('dashboardlogin/agents')->group(function () { /* ... */ });
