<?php

namespace App\Models;

use App\Enums\UserType;
use App\Events\UserCreatedEvent;
use App\Models\Admin\Bank;
use App\Models\Admin\Permission;
use App\Models\Admin\Role;
use App\Models\Report;
use App\Models\SeamlessTransaction;
use Bavix\Wallet\Interfaces\Wallet;
use Bavix\Wallet\Traits\HasWalletFloat;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable implements Wallet
{
    use HasApiTokens, HasFactory, HasWalletFloat, Notifiable;

    private const PLAYER_ROLE = 3;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'user_name',
        'name',
        'profile',
        'email',
        'site_link',
        'password',
        'profile',
        'phone',
        'balance',
        'max_score',
        'agent_id',
        'status',
        'type',
        'is_changed_password',
        'referral_code',
        'agent_logo',
        'payment_type_id',
        'account_number',
        'account_name',
        'line_id',
        'commission',
    ];

    protected $dispatchesEvents = [
        'created' => UserCreatedEvent::class,
    ];

    protected $dates = ['created_at', 'updated_at'];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'type' => UserType::class,
    ];

    public function getIsAdminAttribute()
    {
        return $this->roles()->where('id', 2)->exists();
    }

   

    public function getIsAgentAttribute()
    {
        return $this->roles()->where('id', 3)->exists();
    }

    public function getIsUserAttribute()
    {
        return $this->roles()->where('id', 4)->exists();
    }

    public function roles()
    {
        return $this->belongsToMany(Role::class);
    }

    public function permissions()
    {
        return $this->belongsToMany(Permission::class);
    }

    public function hasRole($role)
    {
        return $this->roles()
            ->where('title', $role)
            ->exists();
    }

    // public function hasPermission($permission)
    // {
    //     return $this->roles->flatMap->permissions->pluck('title')->contains($permission);
    // }

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    

    public static function adminUser()
    {
        return self::where('type', UserType::SuperAdmin)->first();
    }

    

    public function parent()
    {
        return $this->belongsTo(User::class, 'agent_id');
    }

    public function scopeRoleLimited($query)
    {
        if (! Auth::user()->hasRole('Admin')) {
            return $query->where('users.agent_id', Auth::id());
        }

        return $query;
    }

    public function scopePlayer($query)
    {
        return $query->whereHas('roles', function ($query) {
            $query->where('role_id', self::PLAYER_ROLE);
        });
    }

    public static function getPlayersByAgentId(int $agentId)
    {
        return self::where('agent_id', $agentId)
            ->whereHas('roles', function ($query) {
                $query->where('title', '!=', 'Agent');
            })
            ->get();
    }

    public function agent()
    {
        return $this->belongsTo(User::class, 'agent_id');
    }

    public function paymentType()
    {
        return $this->belongsTo(PaymentType::class, 'payment_type_id');
    }

     /**
     * Get the game provider password for this user.
     */
    public function getGameProviderPassword(): ?string
    {
        if ($this->game_provider_password) {
            try {
                return Crypt::decryptString($this->game_provider_password);
            } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
                // Log the error or handle it as appropriate (e.g., return null to regenerate)
                \Log::error('Failed to decrypt game_provider_password for user '.$this->id, ['error' => $e->getMessage()]);

                return null;
            }
        }

        return null;
    }

    /**
     * Set the game provider password for this user.
     */
    public function setGameProviderPassword(string $password): void
    {
        $this->game_provider_password = Crypt::encryptString($password);
        $this->save(); // Save the user model to persist the password
    }

    public function placeBets()
    {
        return $this->hasMany(PlaceBet::class, 'member_account', 'user_name', 'player_id');
    }

    public function hasPermission($permission)
    {
        // If user is a parent agent, they have all permissions
        if ($this->hasRole('Agent')) {
            return true;
        }

        // Get all permissions for the user
        $permissions = $this->getAllPermissions()->pluck('title')->toArray();
        
        // Check if the user has the specific permission
        return in_array($permission, $permissions);
    }

    /**
     * Get all permissions for the user through their roles
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getAllPermissions()
    {
        return $this->roles()
            ->with(['permissions' => function ($query) {
                $query->select('permissions.id', 'permissions.title');
            }])
            ->get()
            ->pluck('permissions')
            ->flatten()
            ->unique('id')
            ->values();
    }

    /**
     * Check if user has any of the given permissions
     *
     * @param array|string $permissions
     * @return bool
     */
    public function hasAnyPermission($permissions)
    {
        $permissions = is_array($permissions) ? $permissions : [$permissions];
        return $this->getAllPermissions()
            ->whereIn('title', $permissions)
            ->isNotEmpty();
    }

    /**
     * Check if user has all of the given permissions
     *
     * @param array|string $permissions
     * @return bool
     */
    public function hasAllPermissions($permissions)
    {
        $permissions = is_array($permissions) ? $permissions : [$permissions];
        return $this->getAllPermissions()
            ->whereIn('title', $permissions)
            ->count() === count($permissions);
    }
}