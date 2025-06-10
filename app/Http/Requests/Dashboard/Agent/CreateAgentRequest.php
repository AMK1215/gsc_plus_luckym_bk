<?php

namespace App\Http\Requests\Dashboard\Agent;

use Illuminate\Foundation\Http\FormRequest;

class CreateAgentRequest extends FormRequest
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
        return [
            'user_name' => [
                'required',
                'string',
                'unique:users,user_name',
                'regex:/^A[A-Z0-9]{6}$/',
                'max:7'
            ],
            'name' => [
                'nullable',
                'string',
                'max:255'
            ],
            'phone' => [
                'required',
                'string',
                'regex:/^09[0-9]{9}$/',
                'max:11'
            ],
            'password' => [
                'required',
                'string',
                'min:6',
                'regex:/^[a-z0-9]+$/'
            ],
            'payment_type_id' => 'required|exists:payment_types,id',
            'account_name' => [
                'required',
                'string',
                'max:255',
                'regex:/^[a-zA-Z\s]+$/'
            ],
            'account_number' => [
                'required',
                'string',
                'max:255',
                'regex:/^[0-9]+$/'
            ],
            'referral_code' => [
                'required',
                'string',
                'unique:users,referral_code',
                'max:8'
            ],
            'line_id' => [
                'nullable',
                'string',
                'max:255',
                'regex:/^[a-zA-Z0-9_]+$/'
            ],
            'commission' => [
                'required',
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
            'user_name.required' => 'Username is required',
            'user_name.unique' => 'Username is already taken',
            'user_name.regex' => 'Username must start with A followed by 6 alphanumeric characters',
            'user_name.max' => 'Username cannot exceed 7 characters',
            
            'name.max' => 'Name cannot exceed 255 characters',
            
            'phone.required' => 'Phone number is required',
            'phone.regex' => 'Phone number must start with 09 followed by 9 digits',
            'phone.max' => 'Phone number cannot exceed 11 digits',
            
            'password.required' => 'Password is required',
            'password.min' => 'Password must be at least 6 characters',
            'password.regex' => 'Password can only contain lowercase letters and numbers',
            
            'payment_type_id.required' => 'Payment type is required',
            'payment_type_id.exists' => 'Invalid payment type',
            
            'account_name.required' => 'Account name is required',
            'account_name.regex' => 'Account name can only contain letters and spaces',
            
            'account_number.required' => 'Account number is required',
            'account_number.regex' => 'Account number can only contain numbers',
            
            'referral_code.required' => 'Referral code is required',
            'referral_code.unique' => 'Referral code is already taken',
            'referral_code.max' => 'Referral code cannot exceed 8 characters',
            
            'line_id.regex' => 'Line ID can only contain letters, numbers, and underscores',
            
            'commission.required' => 'Commission rate is required',
            'commission.numeric' => 'Commission must be a number',
            'commission.min' => 'Commission must be at least 0',
            'commission.max' => 'Commission cannot exceed 100',
            'commission.regex' => 'Commission can have up to 2 decimal places',
            
            'agent_logo.image' => 'The file must be an image',
            'agent_logo.mimes' => 'The image must be a jpeg, png, or jpg',
            'agent_logo.max' => 'The image size cannot exceed 2MB'
        ];
    }
} 