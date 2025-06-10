<?php

namespace App\Http\Controllers\Api\V1\Dashboard\Agent;

use App\Http\Controllers\Controller;
use App\Models\PaymentType;
use App\Traits\HttpResponses;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class AgentUtilityController extends Controller
{
    use HttpResponses;

    /**
     * Generate a random string for username
     */
    public function generateRandomString()
    {
        try {
            $randomNumber = mt_rand(10000000, 99999999);
            $randomString = 'A' . $randomNumber;

            return $this->success(
                ['random_string' => $randomString],
                'Random string generated successfully',
                Response::HTTP_OK
            );
        } catch (\Exception $e) {
            return $this->error(
                null,
                'Failed to generate random string',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Generate a unique referral code
     */
    public function generateReferralCode()
    {
        try {
            $referralCode = strtoupper(Str::random(8));
            
            return $this->success(
                ['referral_code' => $referralCode],
                'Referral code generated successfully',
                Response::HTTP_OK
            );
        } catch (\Exception $e) {
            return $this->error(
                null,
                'Failed to generate referral code',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }

    /**
     * Get all payment types
     */
    public function getPaymentTypes()
    {
        try {
            $paymentTypes = PaymentType::select('id', 'name', 'status')
                ->where('status', 1)
                ->get();
            
            return $this->success(
                $paymentTypes,
                'Payment types retrieved successfully',
                Response::HTTP_OK
            );
        } catch (\Exception $e) {
            return $this->error(
                null,
                'Failed to retrieve payment types',
                Response::HTTP_INTERNAL_SERVER_ERROR
            );
        }
    }
} 