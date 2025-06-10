<?php

namespace App\Http\Controllers\Api\V1\Dashboard;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Http\Requests\Dashboard\LoginRequest;
use App\Http\Resources\Dashboard\AdminResource;
use App\Models\Admin\UserLog;
use App\Models\User;
use Exception;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use App\Traits\HttpResponses;
use App\Http\Requests\Dashboard\ChangePasswordRequest;

class AuthController extends Controller
{
    use HttpResponses;

    private const ADMIN_ROLE = 1;
    private const AGENT_ROLE = 2;
    private const SUPER_ADMIN_ROLE = 4;


    public function login(LoginRequest $request)
    {
        try {
            $data = $request->validated();

            $credentials = is_numeric($data['user_name'])
                ? ['phone' => $data['user_name'], 'password' => $data['password']]
                : ['user_name' => $data['user_name'], 'password' => $data['password']];

            if (!Auth::attempt($credentials)) {
                return $this->error(
                    null,
                    'Invalid credentials',
                    401
                );
            }

            $user = Auth::user();

            if ($user->status == 0) {
                Auth::logout();
                return $this->error(
                    null,
                    'Your account is not activated',
                    403
                );
            }

            if ($user->is_changed_password == 0) {
                return $this->error(
                    [
                        'user_id' => $user->id,
                        'requires_password_change' => true
                    ],
                    'Password change required',
                    200
                );
            }

            // Ensure roles relationship is loaded
            $user->load('roles');

            if ($user->roles->isEmpty() || !in_array($user->roles[0]->id, [self::ADMIN_ROLE, self::SUPER_ADMIN_ROLE, self::AGENT_ROLE])) {
                Auth::logout();
                return $this->error(
                    null,
                    'You do not have permission to access this area',
                    403
                );
            }

            UserLog::create([
                'ip_address' => $request->ip(),
                'user_id' => $user->id,
                'user_agent' => $request->userAgent(),
            ]);

            $user->tokens()->delete();
            $token = $user->createToken($user->user_name)->plainTextToken;

            return $this->success(
                [
                    'user' => new AdminResource($user),
                    'token' => $token,
                    'token_type' => 'Bearer'
                ],
                'Login successful',
                200
            );

        } catch (\Exception $e) {
            Log::error('Login error: ' . $e->getMessage());
            return $this->error(
                null,
                'An error occurred during login',
                500
            );
        }
    }

   

    public function logout(Request $request)
    {
        try {
            $request->user()->currentAccessToken()->delete();
            return $this->success(
                null,
                'Logged out successfully',
                200
            );
        } catch (\Exception $e) {
            Log::error('Logout error: ' . $e->getMessage());
            return $this->error(
                null,
                'An error occurred during logout',
                500
            );
        }
    }

    public function getUser()
    {
        try {
            $user = Auth::user();
            if (!$user) {
                return $this->error(
                    null,
                    'User not found',
                    404
                );
            }
            return $this->success(
                new AdminResource($user),
                'User retrieved successfully',
                200
            );
        } catch (\Exception $e) {
            Log::error('Get user error: ' . $e->getMessage());
            return $this->error(
                null,
                'An error occurred while retrieving user data',
                500
            );
        }
    }

    public function changePassword(ChangePasswordRequest $request)
    {
        try {
            $admin = Auth::user();

            if (!Hash::check($request->current_password, $admin->password)) {
                return $this->error(
                    null,
                    'Current password is incorrect',
                    401
                );
            }

            $admin->update([
                'password' => Hash::make($request->password),
                'status' => 1,
            ]);

            return $this->success(
                null,
                'Password changed successfully',
                200
            );
        } catch (\Exception $e) {
            Log::error('Change password error: ' . $e->getMessage());
            return $this->error(
                null,
                'An error occurred while changing password',
                500
            );
        }
    }
}

