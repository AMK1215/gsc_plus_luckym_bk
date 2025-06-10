<?php

namespace App\Enums;

enum UserType: string
{
    case Admin = 'admin';
    case Agent = 'agent';
    case Player = 'player';
    case SuperAdmin = 'super_admin';

    public static function usernameLength(UserType $type)
    {
        return match ($type) {
            self::Admin => 1,
            self::Agent => 2,
            self::Player => 3,
            self::SuperAdmin => 4,
        };
    }

    public static function childUserType(UserType $type)
    {
        return match ($type) {
            self::SuperAdmin => self::Admin,
            self::Admin => self::Agent,
            self::Agent => self::Player,
            self::Player => self::Player,
        };
    }
}

// enum UserType: int
// {
//     case Admin = 10;
//     case Agent = 20;
//     case Player = 30;

//     public static function usernameLength(UserType $type)
//     {
//         return match ($type) {
//             self::Admin => 1,
//             self::Agent => 2,
//             self::Player => 3,
//         };
//     }

//     public static function childUserType(UserType $type)
//     {
//         return match ($type) {
//             self::Admin => self::Agent,
//             self::Agent => self::Player,
//             self::Player => self::Player
//         };
//     }
// }