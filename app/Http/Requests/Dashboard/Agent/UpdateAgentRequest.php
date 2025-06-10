<?php

namespace App\Http\Requests\Dashboard\Agent;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class UpdateAgentRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $userId = $this->route('agent'); // Assuming the route parameter is named 'agent'

        return [
            'user_name' => [
                'sometimes',
                'string',
                Rule::unique('users', 'user_name')->ignore($userId),
                'regex:/^A[A-Z0-9]{6}$/',
                'max:7'
            ],
            'name' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/^[a-zA-Z\s]+$/'
            ],
            'phone' => [
                'sometimes',
                'string',
                Rule::unique('users', 'phone')->ignore($userId),
                'regex:/^09[0-9]{9}$/',
                'max:11'
            ],
            'password' => [
                'sometimes',
                'string',
                'min:6',
                'regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$/'
            ],
            'payment_type_id' => 'sometimes|exists:payment_types,id',
            'account_name' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/^[a-zA-Z\s]+$/'
            ],
            'account_number' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/^[0-9]+$/'
            ],
            'referral_code' => [
                'sometimes',
                'string',
                Rule::unique('users', 'referral_code')->ignore($userId),
                'regex:/^[A-Z0-9]{8}$/',
                'max:8'
            ],
            'line_id' => [
                'nullable',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_]+$/'
            ],
            'commission' => [
                'sometimes',
                'numeric',
                'min:0',
                'max:100',
                'regex:/^\d+(\.\d{1,2})?$/'
            ],
            'agent_logo' => [
                'nullable',
                'image',
                'mimes:jpeg,png,jpg',
                'max:2048'
            ],
            'status' => [
                'sometimes',
                'boolean'
            ]
        ];
    }

    /**
     * Get custom messages for validator errors.
     *
     * @return array
     */
    public function messages()
    {
        return [
            'user_name.unique' => 'Username is already taken',
            'user_name.regex' => 'Username must start with A followed by 6 alphanumeric characters',
            'user_name.max' => 'Username cannot exceed 7 characters',
            
            'name.regex' => 'Name can only contain letters and spaces',
            
            'phone.unique' => 'Phone number is already registered',
            'phone.regex' => 'Phone number must start with 09 followed by 9 digits',
            'phone.max' => 'Phone number cannot exceed 11 digits',
            
            'password.min' => 'Password must be at least 6 characters',
            'password.regex' => 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
            
            'payment_type_id.exists' => 'Invalid payment type',
            
            'account_name.regex' => 'Account name can only contain letters and spaces',
            
            'account_number.regex' => 'Account number can only contain numbers',
            
            'referral_code.unique' => 'Referral code is already taken',
            'referral_code.regex' => 'Referral code must be 8 alphanumeric characters',
            'referral_code.max' => 'Referral code cannot exceed 8 characters',
            
            'line_id.regex' => 'Line ID can only contain letters, numbers, and underscores',
            
            'commission.numeric' => 'Commission must be a number',
            'commission.min' => 'Commission must be at least 0',
            'commission.max' => 'Commission cannot exceed 100',
            'commission.regex' => 'Commission can have up to 2 decimal places',
            
            'agent_logo.image' => 'The file must be an image',
            'agent_logo.mimes' => 'The image must be a jpeg, png, or jpg',
            'agent_logo.max' => 'The image size cannot exceed 2MB',
            
            'status.boolean' => 'Status must be either true or false'
        ];
    }
} 