<?php

namespace App\Http\Controllers\Api\V1\Dashboard\Agent;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Enums\TransactionName;
use App\Enums\TransactionType;
use App\Enums\UserType;
use App\Http\Requests\Dashboard\AgentRequest;
use App\Http\Requests\Dashboard\Agent\TransferLogRequest;
use App\Models\Admin\TransferLog;
use App\Models\PaymentType;
use App\Models\User;
use App\Services\WalletService;
use Carbon\Carbon;
use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;
use Yajra\DataTables\Contracts\DataTable;
use Yajra\DataTables\Facades\DataTables;
use App\Traits\HttpResponses;
use App\Http\Requests\Dashboard\Agent\CreateAgentRequest;
use Illuminate\Support\Facades\Log;

class AgentController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    use HttpResponses;
    private const AGENT_ROLE = 2;
    private const ADMIN_ROLE = 1;

    public function index(Request $request)
    {
        try {
            $user = Auth::user();
            
            // Check if user has the permission
            if (!$user->hasPermission('agent_index')) {
                return $this->error(
                    [
                        'user_id' => $user->id,
                        'user_roles' => $user->roles->pluck('id'),
                        'permissions' => $user->getAllPermissions()->pluck('title')
                    ],
                    'You do not have permission to access this resource',
                    Response::HTTP_FORBIDDEN
                );
            }

            $query = User::with(['roles', 'paymentType'])
                ->whereHas('roles', function ($query) {
                    $query->where('role_id', self::AGENT_ROLE);
                });

            // If user is not admin, only show their agents
            if (!$user->hasRole('Admin')) {
                $query->where('agent_id', $user->id);
            }

            // Search functionality
            if ($request->has('search')) {
                $search = $request->search;
                $query->where(function($q) use ($search) {
                    $q->where('user_name', 'like', "%{$search}%")
                      ->orWhere('name', 'like', "%{$search}%")
                      ->orWhere('phone', 'like', "%{$search}%")
                      ->orWhere('account_number', 'like', "%{$search}%");
                });
            }

            // Filter by status
            if ($request->has('status')) {
                $query->where('status', $request->status);
            }

            // Filter by date range
            if ($request->has('start_date') && $request->has('end_date')) {
                $query->whereBetween('created_at', [
                    $request->start_date,
                    $request->end_date
                ]);
            }

            // Sorting
            $sortField = $request->input('sort_by', 'created_at');
            $sortDirection = $request->input('sort_direction', 'desc');
            $allowedSortFields = ['created_at', 'name', 'user_name', 'status', 'balance'];
            
            if (in_array($sortField, $allowedSortFields)) {
                $query->orderBy($sortField, $sortDirection);
            }

            // Pagination
            $perPage = $request->input('per_page', 10);
            $users = $query->paginate($perPage);

            // Transform the response to include additional data
            $users->getCollection()->transform(function ($user) {
                return [
                    'id' => $user->id,
                    'user_name' => $user->user_name,
                    'name' => $user->name,
                    'phone' => $user->phone,
                    'site_link' => $user->site_link,
                    'balance' => $user->balanceFloat,
                    'email' => $user->email,
                    'status' => $user->status,
                    'is_changed_password' => $user->is_changed_password,
                    'agent_id' => $user->agent_id,
                    'payment_type' => $user->paymentType ? [
                        'id' => $user->paymentType->id,
                        'name' => $user->paymentType->name
                    ] : null,
                    'referral_code' => $user->referral_code,
                    'agent_logo' => $user->agent_logo,
                    'account_name' => $user->account_name,
                    'account_number' => $user->account_number,
                    'line_id' => $user->line_id,
                    'commission' => $user->commission,
                    'created_at' => $user->created_at,
                    'updated_at' => $user->updated_at,
                    'type' => $user->type,
                    'roles' => $user->roles->map(function ($role) {
                        return [
                            'id' => $role->id,
                            'title' => $role->title
                        ];
                    })
                ];
            });

            return $this->success(
                [
                    'agents' => $users->items(),
                    'pagination' => [
                        'total' => $users->total(),
                        'per_page' => $users->perPage(),
                        'current_page' => $users->currentPage(),
                        'last_page' => $users->lastPage(),
                        'from' => $users->firstItem(),
                        'to' => $users->lastItem()
                    ]
                ],
                'Agents retrieved successfully',
                Response::HTTP_OK
            );

        } catch (\Exception $e) {
            return $this->error(
                [
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ],
                'An error occurred while retrieving agents',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        if (Gate::denies('agent_create')) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }
        $agent_name = $this->generateRandomString();
        $referral_code = $this->generateReferralCode();
        $paymentTypes = PaymentType::all();

        return $this->success([
            'agent_name' => $agent_name,
            'referral_code' => $referral_code,
            'payment_types' => $paymentTypes
        ], 'Create agent data fetched successfully');
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(AgentRequest $request)
    {
        Log::info('Agent store request received', [
            'request_data' => $request->all(),
            'user' => Auth::user()
        ]);
        try {
            $user = Auth::user();
            
            // Check if user has the permission
            if (!$user->hasPermission('agent_create')) {
                Log::warning('User does not have permission to create agent', ['user_id' => $user->id]);
                return $this->error(
                    null,
                    'You do not have permission to create agents',
                    Response::HTTP_FORBIDDEN
                );
            }

            $data = $request->validated();
            Log::info('Validated agent data', $data);
            
            // Create the agent
            $agent = User::create([
                'user_name' => $data['user_name'],
                'name' => $data['name'],
                'site_link' => $data['site_link'],
                'phone' => $data['phone'],
                'password' => Hash::make($data['password']),
                'payment_type_id' => $data['payment_type_id'],
                'account_name' => $data['account_name'],
                'account_number' => $data['account_number'],
                'referral_code' => $data['referral_code'],
                'line_id' => $data['line_id'] ?? null,
                'commission' => $data['commission'],
                'agent_id' => $user->id,
                'status' => 1,
                'is_changed_password' => 0,
                'type' => 'agent'
            ]);
            Log::info('Agent created', ['agent_id' => $agent->id]);

            // Assign agent role
            $agent->roles()->attach(self::AGENT_ROLE);
            Log::info('Agent role attached', ['agent_id' => $agent->id]);

            return $this->success(
                [
                    'agent' => $agent->load('roles', 'paymentType'),
                    'site_link' => $data['site_link'],
                    'referral_code' => $data['referral_code'],
                    'user_name' => $data['user_name'],
                    'password' => $data['password']
                    
                ],
                'Agent created successfully',
                Response::HTTP_CREATED
            );

        } catch (\Exception $e) {
            \Log::error('Error creating agent', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'request_data' => $request->all()
            ]);
            return $this->error(
                [
                    'error' => $e->getMessage(),
                    'trace' => $e->getTraceAsString()
                ],
                'An error occurred while creating the agent',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        if (Gate::denies('agent_show')) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        $user_detail = User::find($id);

        return $this->success([
            'user_detail' => $user_detail
        ], 'Agent detail fetched successfully');
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        if (Gate::denies('agent_edit') || ! $this->ifChildOfParent(request()->user()->id, $id)) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        $agent = User::find($id);
        $paymentTypes = PaymentType::all();

        return $this->success([
            'agent' => $agent,
            'payment_types' => $paymentTypes
        ], 'Edit agent data fetched successfully');
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        $param = $request->validate([
            'name' => 'required|string',
            'phone' => ['nullable', 'regex:/^([0-9\s\-\+\(\)]*)$/', 'unique:users,phone,' . $id],
            'payment_type_id' => 'required|exists:payment_types,id',
            'account_number' => 'required|string',
            'account_name' => 'required|string',
            'line_id' => 'nullable',
            'commission' => 'nullable',
        ]);

        $user = User::find($id);
        if ($request->file('agent_logo')) {
            $image = $request->file('agent_logo');
            $ext = $image->getClientOriginalExtension();
            $filename = uniqid('logo_') . '.' . $ext;
            $image->move(public_path('assets/img/sitelogo/'), $filename);

            $param['agent_logo'] = $filename;
        }

        $user->update($param);

        return redirect()->back()
            ->with('success', 'Agent Updated successfully');
    }

    /**
     * Remove the specified resource from storage.
     */
   
     // get admin balance
     public function getAdminBalance()
     {
        $admin = Auth::user();
        return $this->success([
            'balance' => $admin->balanceFloat
        ], 'Admin balance fetched successfully');
     }

    public function makeCashIn(TransferLogRequest $request, $id)
    {
        
        $user = Auth::user();

        if (!$user->hasPermission('make_transfer')) {
            return $this->error(
                [
                    'user_id' => $user->id,
                    'user_roles' => $user->roles->pluck('id'),
                    'permissions' => $user->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        try {
            $inputs = $request->validated();
            $agent = User::findOrFail($id);
            $admin = Auth::user();
            $cashIn = $inputs['amount'];
            if ($cashIn > $admin->balanceFloat) {
                return $this->error(null, 'You do not have enough balance to transfer!', 400);
            }

            // Transfer money
            app(WalletService::class)->transfer($admin, $agent, $request->validated('amount'), TransactionName::CreditTransfer, ['note' => $request->note]);

            return $this->success([
                'agentId' => $agent->id,
                'amount' => $cashIn,
                'adminBalance' => $admin->balanceFloat,
                'agentBalance' => $agent->balanceFloat,
            ], 'Money fill request submitted successfully!');
        } catch (Exception $e) {
            return $this->error([
                'error' => $e->getMessage(),
                'trace' => config('app.debug') ? $e->getTraceAsString() : null
            ], $e->getMessage(), 500);
        }
    }

    public function makeCashOut(TransferLogRequest $request, string $id)
    {
        
        $user = Auth::user();

        if (!$user->hasPermission('make_transfer')) {
            return $this->error(
                [
                    'user_id' => $user->id,
                    'user_roles' => $user->roles->pluck('id'),
                    'permissions' => $user->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        try {
            $inputs = $request->validated();
            $agent = User::findOrFail($id);
            $admin = Auth::user();
            $cashOut = $inputs['amount'];

            if ($cashOut > $agent->balanceFloat) {
                return $this->error(null, 'You do not have enough balance to transfer!', 400);
            }

            // Transfer money
            app(WalletService::class)->transfer($agent, $admin, $request->validated('amount'), TransactionName::DebitTransfer, ['note' => $request->note]);

            return $this->success([
                'agentId' => $agent->id,
                'amount' => $cashOut,
                'adminBalance' => $admin->balanceFloat,
                'agentBalance' => $agent->balanceFloat,
            ], 'Money fill request submitted successfully!');
        } catch (Exception $e) {
            return $this->error([
                'error' => $e->getMessage(),
                'trace' => config('app.debug') ? $e->getTraceAsString() : null
            ], $e->getMessage(), 500);
        }
    }

    public function getTransferDetail($id)
    {
        if (Gate::denies('make_transfer') || ! $this->ifChildOfParent(request()->user()->id, $id)) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }
        $transfer_detail = TransferLog::where('from_user_id', $id)
            ->orWhere('to_user_id', $id)
            ->get();

        return $this->success([
            'transfer_detail' => $transfer_detail
        ], 'Transfer detail fetched successfully');
    }

    private function generateRandomString()
    {
        $randomNumber = mt_rand(10000000, 99999999);

        return 'LKM' . $randomNumber;
    }

    public function banAgent($id)
    {
        if (! $this->ifChildOfParent(request()->user()->id, $id)) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        $user = User::find($id);
        $user->update(['status' => $user->status == 1 ? 0 : 1]);
        if (Auth::check() && Auth::id() == $id) {
            Auth::logout();
        }

        return $this->success([
            'user_id' => $user->id,
            'status' => $user->status
        ], 'User ' . ($user->status == 1 ? 'activated' : 'banned') . ' successfully');
    }

    public function getChangePassword($id)
    {
        if (Gate::denies('agent_change_password_access') || ! $this->ifChildOfParent(request()->user()->id, $id)) {
            return $this->error(
                [
                    'user_id' => Auth::id(),
                    'permissions' => Auth::user()->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        $agent = User::find($id);

        return $this->success([
            'agent' => $agent
        ], 'Change password data fetched successfully');
    }

    public function makeChangePassword($id, Request $request)
    {
        
        $user = Auth::user();

        if (!$user->hasPermission('agent_change_password_access')) {
            return $this->error(
                [
                    'user_id' => $user->id,
                    'user_roles' => $user->roles->pluck('id'),
                    'permissions' => $user->getAllPermissions()->pluck('title')
                ],
                'You do not have permission to access this resource',
                Response::HTTP_FORBIDDEN
            );
        }

        $request->validate([
            'password' => 'required|min:6|confirmed',
        ]);

        $agent = User::find($id);
        $agent->update([
            'password' => Hash::make($request->password),
        ]);

            return redirect()->back()
                ->with('success', 'Agent Change Password successfully')
                ->with('password', $request->password)
                ->with('username', $agent->user_name);
    }

    private function generateReferralCode($length = 8)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';

        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[rand(0, $charactersLength - 1)];
        }

        return $randomString;
    }

    public function showAgentLogin($id)
    {
        $agent = User::findOrFail($id);

        return view('auth.agent_login', compact('agent'));
    }

    public function AgentToPlayerDepositLog()
    {
        $transactions = DB::table('transactions')
            ->join('users as players', 'players.id', '=', 'transactions.payable_id')
            ->join('users as agents', 'agents.id', '=', 'players.agent_id')
            ->where('transactions.type', 'deposit')
            ->where('transactions.name', 'credit_transfer')
            ->where('agents.id', '<>', 1) // Exclude agent_id 1
            ->groupBy('agents.id', 'players.id', 'agents.name', 'players.name', 'agents.commission')
            ->select(
                'agents.id as agent_id',
                'agents.name as agent_name',
                'players.id as player_id',
                'players.name as player_name',
                'agents.commission as agent_commission', // Get the commission percentage
                DB::raw('count(transactions.id) as total_deposits'),
                DB::raw('sum(transactions.amount) as total_amount')
            )
            ->get();

        return view('admin.agent.agent_to_play_dep_log', compact('transactions'));
    }

    public function AgentToPlayerDetail($agent_id, $player_id)
    {
        // Retrieve detailed information about the agent and player
        $transactionDetails = DB::table('transactions')
            ->join('users as players', 'players.id', '=', 'transactions.payable_id')
            ->join('users as agents', 'agents.id', '=', 'players.agent_id')
            ->where('agents.id', $agent_id)
            ->where('players.id', $player_id)
            ->where('transactions.type', 'deposit')
            ->where('transactions.name', 'credit_transfer')
            ->select(
                'agents.name as agent_name',
                'players.name as player_name',
                'transactions.amount',
                'transactions.created_at',
                'agents.commission as agent_commission'
            )
            ->get();

        return view('admin.agent.agent_to_player_detail', compact('transactionDetails'));
    }

    public function AgentWinLoseReport(Request $request)
    {
        $query = DB::table('reports')
            ->join('users', 'reports.agent_id', '=', 'users.id')
            ->select(
                'reports.agent_id',
                'users.name as agent_name',
                DB::raw('COUNT(DISTINCT reports.id) as qty'),
                DB::raw('SUM(reports.bet_amount) as total_bet_amount'),
                DB::raw('SUM(reports.valid_bet_amount) as total_valid_bet_amount'),
                DB::raw('SUM(reports.payout_amount) as total_payout_amount'),
                DB::raw('SUM(reports.commission_amount) as total_commission_amount'),
                DB::raw('SUM(reports.jack_pot_amount) as total_jack_pot_amount'),
                DB::raw('SUM(reports.jp_bet) as total_jp_bet'),
                DB::raw('(SUM(reports.payout_amount) - SUM(reports.valid_bet_amount)) as win_or_lose'),
                DB::raw('COUNT(*) as stake_count'),
                DB::raw('DATE_FORMAT(reports.created_at, "%Y %M") as report_month_year')
            );

        // Apply the date filter if provided
        if ($request->has('start_date') && $request->has('end_date')) {
            $query->whereBetween('reports.created_at', [$request->start_date, $request->end_date]);
        } elseif ($request->has('month_year')) {
            // Filter by month and year if provided
            $monthYear = Carbon::parse($request->month_year);
            $query->whereMonth('reports.created_at', $monthYear->month)
                ->whereYear('reports.created_at', $monthYear->year);
        } else {
            $currentMonthStart = Carbon::now()->startOfMonth()->format('Y-m-d H:i:s');
            $currentMonthEnd = Carbon::now()->endOfMonth()->format('Y-m-d H:i:s');

            $query->whereBetween('reports.created_at', [$currentMonthStart, $currentMonthEnd]);
        }

        $agentReports = $query->groupBy('reports.agent_id', 'users.name', 'report_month_year')->get();

        return view('admin.agent.agent_report_index', compact('agentReports'));
    }

    public function AgentWinLoseDetails(Request $request, $agent_id)
    {
        if ($request->ajax()) {
            $details = DB::table('reports')
                ->join('users', 'reports.agent_id', '=', 'users.id')
                ->where('reports.agent_id', $agent_id)
                ->select(
                    'reports.*',
                    'users.name as agent_name',
                    'users.commission as agent_comm',
                    DB::raw('(reports.payout_amount - reports.valid_bet_amount) as win_or_lose') // Calculating win_or_lose
                )
                ->get();

            return DataTables::of($details)
                ->make(true);
        }

        return view('admin.agent.win_lose_details');
    }

    public function AuthAgentWinLoseReport(Request $request)
    {
        $agentId = Auth::user()->id;  // Get the authenticated user's agent_id

        $query = DB::table('reports')
            ->join('users', 'reports.agent_id', '=', 'users.id')
            ->select(
                'reports.agent_id',
                'users.name as agent_name',
                DB::raw('COUNT(DISTINCT reports.id) as qty'),
                DB::raw('SUM(reports.bet_amount) as total_bet_amount'),
                DB::raw('SUM(reports.valid_bet_amount) as total_valid_bet_amount'),
                DB::raw('SUM(reports.payout_amount) as total_payout_amount'),
                DB::raw('SUM(reports.commission_amount) as total_commission_amount'),
                DB::raw('SUM(reports.jack_pot_amount) as total_jack_pot_amount'),
                DB::raw('SUM(reports.jp_bet) as total_jp_bet'),
                DB::raw('(SUM(reports.payout_amount) - SUM(reports.valid_bet_amount)) as win_or_lose'),
                DB::raw('COUNT(*) as stake_count'),
                DB::raw('DATE_FORMAT(reports.created_at, "%Y %M") as report_month_year')
            )
            ->where('reports.agent_id', $agentId);  // Filter by authenticated user's agent_id

        // Apply the date filter if provided
        if ($request->has('start_date') && $request->has('end_date')) {
            $query->whereBetween('reports.created_at', [$request->start_date, $request->end_date]);
        } elseif ($request->has('month_year')) {
            // Filter by month and year if provided
            $monthYear = Carbon::parse($request->month_year);
            $query->whereMonth('reports.created_at', $monthYear->month)
                ->whereYear('reports.created_at', $monthYear->year);
        }

        $agentReports = $query->groupBy('reports.agent_id', 'users.name', 'report_month_year')->get();

        return view('admin.agent.auth_agent_report_index', compact('agentReports'));
    }

    public function AuthAgentWinLoseDetails($agent_id, $month)
    {
        $details = DB::table('reports')
            ->join('users', 'reports.agent_id', '=', 'users.id')
            ->where('reports.agent_id', $agent_id)
            ->whereMonth('reports.created_at', Carbon::parse($month)->month)
            ->whereYear('reports.created_at', Carbon::parse($month)->year)
            ->select(
                'reports.*',
                'users.name as agent_name',
                'users.commission as agent_comm',
                DB::raw('(reports.payout_amount - reports.valid_bet_amount) as win_or_lose') // Calculating win_or_lose
            )
            ->paginate(20);

        return view('admin.agent.auth_win_lose_details', compact('details'));
    }
}
