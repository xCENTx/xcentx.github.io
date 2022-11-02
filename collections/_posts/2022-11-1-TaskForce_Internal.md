---
title: Task Force - Internal Menu
category: Menu
date: 2022-11-1
encrypted_text: true
---

<p align="center">
<img src="https://i.imgur.com/SlppBsz.png">
</p>

# Game Summary
> Release Date: August 26, 2022  
> Game Engine: Unreal Engine v4.26

Task Force is a game that was created by a few SOCOM fans. SOCOM was a popular 3rd person tactical shooter on the PlayStation 2 back in the early 2000's. Due to SONY not making a SOCOM since the PlayStation 3, there have been a lot of fan recreations. CS GO, Insurgency and Fortnite are some games which have special modes / mods that can be downloaded to play a socom like experience.  

For a SOCOM "Remake" Task Force did a decent job at capturing what made SOCOM such a great experience. 
> - Round based game modes with 1 life 
> - Tactical game modes such as Extraction and Demolition
> - Integrated Voice Comms w/ 1 user speaking at a time

While Task Force captured some of the things that made SOCOM a great experience .... It also missed on some of the hallmarks that a SOCOM fan expects from the franchise and its recreations.  
> - Leaderboards
> - Clans
> - Lobbies
> - Playerbase

A game like Task Force would have a hard time surviving in todays gaming landscape. Most people do not want to watch somebody stare at a wall for 3 minutes waiting for the next round. Then there's grenade spam at the start of each match , basically forcing you to rush to cover dodging all the incoming grenades. The first 30 seconds of a round are really hectic but its a steep fall off from there.

The community had high hopes for this game, unfortunately the development team were not able to keep up with the momentum. Seemingly 1 negative review on Steam was enough to make the developer switch directions and start attacking his consumers. On the day of release (SOCOMs Anniversary) BigFryTV decided to stream gameplay for his community and was also banned within 30 minutes for saying something negative about the games spawn system. Overall the devs and community manager attitude seemed to kill the game. Although there is promise for the game to return someday.

# Creating a Task Force Cheat
Creating cheats for Task Force is is a trivial matter. There is a few different steps a user can take but the end result is generally the same. Since Task Force is an Unreal Engine game the very first thing one should do is attempt to dump the game with a tool like Knackers or Cake San dumpers. These are vital assets that can reveal classes, offsets and functions. The following video demonstrates some of the things possible

 {% include youtube.html id="xtklbBi1ET4" %}

## Important Classes  
- UWorld
- APlayerController
- ACharacter
- ATaskForceCharacter
- ATaskForceWeapon

## Important Functions  
- | Function 										  | Description 														|  
- | AActor::IsA 									  | Used to determine if entity is Class Type defined 					|  
- | APawn::GetActorBounds   						  | Used to get the actors dimensions such as height and width 			|  
- | APlayerController::LineOfSightTo 				  | Used to determine if EntityA can visually see EntityB 				|  
- | APlayerController::ProjectWorldLocationToScreen   | Used to draw a location in the game world on the 2D screen space 	|  
- | ATaskForceCharacter::IsAlive 					  | Used to determine if entity is alive 								|  
- | ATaskForceCharacter::IsBot  					  | Used to determine if entity is a bot 								|  
- | ATaskForceCharacter::ThrowProjectile 			  | Used to throw an object 											|  

## Cheat Features  
- Rapid Fire
- No Recoil
- Fly Mode
- Spoof Name
- Spam Chat

# Code Samples

`Perfect Shot`
```cpp
void PerfectShot()
{
	auto WORLD = reinterpret_cast<UWorld**>(dwGameBase + g_GameData->offsets.oUWorld); if ((*WORLD) == nullptr) return;
	auto GAME_STATE = (*WORLD)->GameState; if ((GAME_STATE) == nullptr) return;
	auto LOCAL_PLAYER = (*WORLD)->OwningGameInstance->LocalPlayers[0]; if ((LOCAL_PLAYER) == nullptr) return;
	auto* PLAYER_CONTROLLER = LOCAL_PLAYER->PlayerController; if ((PLAYER_CONTROLLER) == nullptr) return;
	auto PAWN = PLAYER_CONTROLLER->AcknowledgedPawn; if ((PAWN) == nullptr) return;
	auto* ROOT_COMPONENT = PAWN->RootComponent; if ((ROOT_COMPONENT) == nullptr) return;
	ATaskForceCharacter* character = static_cast<ATaskForceCharacter*>(PAWN);
	ATaskForceWeapon* CWeapon = static_cast<ATaskForceWeapon*>(character->CurrentWeapon); if ((CWeapon) == nullptr) return;
	if (!character->IsAlive()) return;

    // Apply Patch
	CWeapon->WeaponConfig.RecoilAdditiveFactor = NULL;
	CWeapon->WeaponConfig.RecoilAdditiveMax = NULL;
	CWeapon->WeaponConfig.RecoilAdditiveRate = NULL;
	CWeapon->WeaponConfig.RecoilDelayTime = NULL;
	CWeapon->WeaponConfig.RecoilMax = NULL;
	CWeapon->WeaponConfig.RecoilPitchMax = NULL;
	CWeapon->WeaponConfig.RecoilPitchMin = NULL;
	CWeapon->WeaponConfig.RecoilRate = NULL;
	CWeapon->WeaponConfig.RecoilResetTime = NULL;
	CWeapon->WeaponConfig.RecoilYawMax = NULL;
	CWeapon->WeaponConfig.RecoilYawMin = NULL;
	CWeapon->WeaponConfig.SpreadAngle = NULL;
	CWeapon->WeaponConfig.SpreadMax = NULL;
	CWeapon->WeaponConfig.SpreadMin = NULL;
	CWeapon->WeaponConfig.SpreadRatio = NULL;
}
```

`Rapid Fire`
```cpp
void RapidFire()
{
	auto WORLD = reinterpret_cast<UWorld**>(dwGameBase + g_GameData->offsets.oUWorld); if ((*WORLD) == nullptr) return;
	auto GAME_STATE = (*WORLD)->GameState; if ((GAME_STATE) == nullptr) return;
	auto LOCAL_PLAYER = (*WORLD)->OwningGameInstance->LocalPlayers[0]; if ((LOCAL_PLAYER) == nullptr) return;
	auto* PLAYER_CONTROLLER = LOCAL_PLAYER->PlayerController; if ((PLAYER_CONTROLLER) == nullptr) return;
	auto PAWN = PLAYER_CONTROLLER->AcknowledgedPawn; if ((PAWN) == nullptr) return;
	auto* ROOT_COMPONENT = PAWN->RootComponent; if ((ROOT_COMPONENT) == nullptr) return;
	ATaskForceCharacter* ATFCharacter = static_cast<ATaskForceCharacter*>(PAWN);
	ATaskForceWeapon* CWeapon = static_cast<ATaskForceWeapon*>(ATFCharacter->CurrentWeapon); if ((CWeapon) == nullptr) return;
	if (!ATFCharacter->IsAlive()) return;

    // Apply Patch
	CWeapon->WeaponConfig.RoundsPerMinute = g_Menu->fRapidFire;
	CWeapon->WeaponConfig.BurstRoundsPerMinute = g_Menu->fRapidFire;
	ATFCharacter->ThrowProjectile();        	// Rapid Projectiles
}
```

`Projectile ESP`
```cpp
void ProjectileESP()
{
	// ESTABLISH SCREEN POSITION
	float X = g_GameVariables->Proc.WindowWidth;
	float Y = g_GameVariables->Proc.WindowHeight;
	Vector2 WindowPos = g_GameVariables->Proc.WindowPos;
	Vector2 pos = { (X / 2), (Y / 2) };     // Center
	auto ImDraw = ImGui::GetWindowDrawList();

	// ESTABLISH DRAW POSITION
	ImVec2 drawPosition = { ((X / 2) + g_GameVariables->Proc.WindowPos.x), g_GameVariables->Proc.WindowPos.y };

	// MATCH INFORMATION
	auto WORLD = reinterpret_cast<UWorld**>(dwGameBase + g_GameData->offsets.oUWorld); if ((*WORLD) == nullptr) return;
	auto GAME_STATE = (*WORLD)->GameState; if ((GAME_STATE) == nullptr) return;
	auto PERSISTENT_LEVEL = (*WORLD)->PersistentLevel; if ((PERSISTENT_LEVEL) == nullptr) return;
	auto LOCAL_PLAYER = (*WORLD)->OwningGameInstance->LocalPlayers[0]; if ((LOCAL_PLAYER) == nullptr) return;
	auto* PLAYER_CONTROLLER = LOCAL_PLAYER->PlayerController; if ((PLAYER_CONTROLLER) == nullptr) return;
	auto PAWN = PLAYER_CONTROLLER->AcknowledgedPawn; if ((PAWN) == nullptr) return;
	auto* ROOT_COMPONENT = PAWN->RootComponent; if ((ROOT_COMPONENT) == nullptr) return;
	ATaskForceCharacter* pATFCharacter = static_cast<ATaskForceCharacter*>(PAWN);
	if (!pATFCharacter->IsAlive()) return;

    //  Begin Looping Actor Array
	auto Actor_Array = PERSISTENT_LEVEL->Actors;
	for (int i = 0; i < Actor_Array.Count(); i++)
	{
		int Type = { 0 };
		auto Current_Actor = Actor_Array[i];
		{
			if (Current_Actor == nullptr) continue;
			if (Current_Actor->RootComponent == nullptr) continue;
			if (!Current_Actor->IsA(ABP_Projectile_M67_C::StaticClass())) continue;     //  Check if Current Actor is a Frag Grenade
		}

		// 3D Boxes
		FVector actorORIGIN;
		FVector actorBOX;
		Current_Actor->GetActorBounds(true, &actorORIGIN, &actorBOX);
		Vector3 ObjectPosition{
			actorORIGIN.X,
			actorORIGIN.Y,
			(actorORIGIN.Z - actorBOX.Z) // CENTERS BOX TO NODE POINT
		};
		Vector2 ObjectSize{ actorBOX.X, (actorBOX.Z * 2) };

		FVector2D screen;
		if (!PLAYER_CONTROLLER->ProjectWorldLocationToScreen(actorORIGIN, &screen, false)) continue;

		Vector3 PlayerPosition{
			ROOT_COMPONENT->RelativeLocation.X,
			ROOT_COMPONENT->RelativeLocation.Y,
			ROOT_COMPONENT->RelativeLocation.Z
		};

		float Distance = (g_GameFunctions->GetDistanceTo3D_Object(PlayerPosition, ObjectPosition) / 10);
		if (Distance >= 500) continue;
		ImVec2 BottomCenterBox = ImVec2((screen.X + WindowPos.x), (screen.Y + WindowPos.y));
		{
			char data[128] = { 0 };
			const char* DrawnDistance = "GRENADE\nDISTANCE: [%.00fm]";
            sprintf_s(data, DrawnDistance, Distance);
			{
				ImDraw->AddText(BottomCenterBox, ImColor(255, 255, 255, 255), data);
				ImDraw->AddCircleFilled(BottomCenterBox, 3, ImColor(255, 0, 0, 150));
			}
		}
	}
}
```