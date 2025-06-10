<?php

namespace App\Http\Requests\Dashboard\Agent;

use Illuminate\Foundation\Http\FormRequest;

class ListAgentRequest extends FormRequest
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
            'search' => 'nullable|string|max:255',
            'status' => 'nullable|boolean',
            'payment_type_id' => 'nullable|exists:payment_types,id',
            'sort_by' => [
                'nullable',
                'string',
                'in:user_name,name,phone,commission,created_at,status'
            ],
            'sort_direction' => [
                'nullable',
                'string',
                'in:asc,desc'
            ],
            'per_page' => [
                'nullable',
                'integer',
                'min:1',
                'max:100'
            ],
            'page' => [
                'nullable',
                'integer',
                'min:1'
            ],
            'date_from' => [
                'nullable',
                'date',
                'before_or_equal:date_to'
            ],
            'date_to' => [
                'nullable',
                'date',
                'after_or_equal:date_from'
            ],
            'commission_min' => [
                'nullable',
                'numeric',
                'min:0',
                'max:100',
                'lte:commission_max'
            ],
            'commission_max' => [
                'nullable',
                'numeric',
                'min:0',
                'max:100',
                'gte:commission_min'
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
            'search.max' => 'Search term cannot exceed 255 characters',
            
            'status.boolean' => 'Status must be either true or false',
            
            'payment_type_id.exists' => 'Invalid payment type',
            
            'sort_by.in' => 'Invalid sort field. Allowed fields are: user_name, name, phone, commission, created_at, status',
            
            'sort_direction.in' => 'Sort direction must be either asc or desc',
            
            'per_page.integer' => 'Items per page must be a number',
            'per_page.min' => 'Items per page must be at least 1',
            'per_page.max' => 'Items per page cannot exceed 100',
            
            'page.integer' => 'Page number must be a number',
            'page.min' => 'Page number must be at least 1',
            
            'date_from.date' => 'Invalid start date format',
            'date_from.before_or_equal' => 'Start date must be before or equal to end date',
            
            'date_to.date' => 'Invalid end date format',
            'date_to.after_or_equal' => 'End date must be after or equal to start date',
            
            'commission_min.numeric' => 'Minimum commission must be a number',
            'commission_min.min' => 'Minimum commission must be at least 0',
            'commission_min.max' => 'Minimum commission cannot exceed 100',
            'commission_min.lte' => 'Minimum commission must be less than or equal to maximum commission',
            
            'commission_max.numeric' => 'Maximum commission must be a number',
            'commission_max.min' => 'Maximum commission must be at least 0',
            'commission_max.max' => 'Maximum commission cannot exceed 100',
            'commission_max.gte' => 'Maximum commission must be greater than or equal to minimum commission'
        ];
    }
} 