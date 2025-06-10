<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        $this->call([
            PaymentTypeTableSeeder::class,
            PermissionsTableSeeder::class,
            //SubAgentPermissionSeeder::class,
            RolesTableSeeder::class,
            PermissionRoleTableSeeder::class,
            UsersTableSeeder::class,
            RoleUserTableSeeder::class,
            BannerSeeder::class,
            BannerTextSeeder::class,
            BannerAdsSeeder::class,
            BankTableSeeder::class,
            WinnerTextSeeder::class,
            TopTenWithdrawSeeder::class,
            ContactTypeSeeder::class,
            ContactSeeder::class,
            PromotionSeeder::class,
            AdsVedioSeeder::class,
            GameTypeTableSeeder::class,
            GscPlusProductTableSeeder::class,
            GameTypeProductTableSeeder::class,
            PragmaticPlaySlotGameListSeeder::class,
            SEOGameListSeeder::class,
            YEEBETGameListSeeder::class,
            PlayTechGameSeeder::class,
            PlayTechLiveCasinoGameSeeder::class,
            JokerSlotGameSeeder::class,
            JokerOtherGameSeeder::class,
            JokerFishingGameSeeder::class,
            SAGamingCasinoGameSeeder::class,
            SpadeGamingSlotGameSeeder::class,
            SpadeGamingFishingGameSeeder::class,
            Live22SlotGameSeeder::class,
            WMCasinoGameSeeder::class,
            HabaneroSlotGameSeeder::class,
            AWCSlotGameSeeder::class,
            AWCFishingGameSeeder::class,
            SabaSportBookGameSeeder::class,
            PGSoftSlotGameSeeder::class,
            PragmaticPlayLiveCasinoPremiumGameSeeder::class,
            PragmaticPlayVirtualSportGameSeeder::class,
            PragmaticPlayLiveCasinoGameSeeder::class,
            DreamGamingSeeder::class,
            BigGamingFishingSeeder::class,
            EvoPlayGameSeeder::class,
            JDBSLOTGameSeeder::class,
            JDBSFishingameSeeder::class,
            JDBOtherGameSeeder::class,
            PlayStarGameSeeder::class,
            CT855CasinoGameSeeder::class,
            CQ9SlotGameSeeder::class,
            CQ9FishingGameSeeder::class,
            JILISlotGameSeeder::class,
            JILICasinoGameSeeder::class,
            JILIFishingGameSeeder::class,
            JILIPokerGameSeeder::class,
            HACKSAWSlotGameSeeder::class,
            HACKSAWOtherGameSeeder::class,
            ImoonOtherGameSeeder::class,
            EpicwinGameSeeder::class,
            FACHAISLOTGameSeeder::class,
            FACHAIFishingGameSeeder::class,
            Rich88SlotGameSeeder::class,
            N2SlotGameSeeder::class,
            AILiveCasinoGameSeeder::class,
            AIPokerGameSeeder::class,
            SmartSoftGameSeeder::class,
            WorldEntertainmentSlotGameSeeder::class,
           
        ]);
    }
}
