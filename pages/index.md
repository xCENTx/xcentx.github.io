---
layout: default
post_list: false
toc: false
comment: true
home_btn: true
btn_text: true
footer: true
title: ""
author: ""
encrypted_text: true
permalink: /
---

<p align="center">
<img src="https://i.imgur.com/SlppBsz.png">
</p>

# Game Summary
Release Date: August 26, 2022  
Game Engine: Unreal Engine v4.26

Task Force is a game that was created by a few SOCOM fans. SOCOM was a popular 3rd person tactical shooter on the PlayStation 2 back in the early 2000's (in fact this forum houses some topics on the game dating that far back!) Due to SONY not making a SOCOM since the PlayStation 3, there have been a lot of fan recreations. CS GO, Insurgency and Fortnite are some games which have special modes / mods that can be downloaded to play a socom like experience. 

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

The community had high hopes for this game, unfortunately the development team were not able to keep up with the momentum. Seemingly 1 negative review on Steam was enough to make the developer switch directions and start attacking his consumers. On the day of release (SOCOMCs Anniversary) BigFryTV decided to stream gameplay for his community and was also banned within 30 minutes for saying something negative about the games spawn system. Overall the devs and community manager attitude seemed to kill the game. Although there is promise for the game to return someday.

# Creating a Task Force Cheat
- Provided is a Task Force SDK.

Creating cheats for Task Force is is a trivial matter. There is a few different steps a user can take but the end result is generally the same. Since Task Force is an Unreal Engine game the very first thing one should do is attempt to dump the game with a tool like Knackers or Cake San dumpers. These are vital assets that can reveal classes, offsets and functions. 

**Important Classes**  
- UWorld
- APlayerController
- ACharacter
- ATaskForceCharacter
- ATaskForceWeapon

**Important Functions**
- IsA() 		|	Used to determine if entity is Class Type defined
- IsAlive() |	Used to determine if entity is alive
- IsBot()	|	Used to determine if entity is a bot
- GetActorBounds() |	Used to get the actors dimensions such as height and width
- ProjectWorldLocationToScreen()	|	Used to draw a location in the game world on the 2D screen space
- ThrowProjectile()	|	Used to throw an object
- LineOfSightTo() 	|	Used to determine if EntityA can visually see EntityB


**Cheat Features**
- ESP
- Aimbot
- Infinite Ammo
- Rapid Fire
- No Recoil
- Fly Mode
- Spoof Name
- Spam Chat