---
title: Accessing PCSX2 Memory
category: Memory Management
date: 2022-11-2
encrypted_text: true
publish: true
---

<p align="center">
<img src="https://forums.pcsx2.net/images/darktheme/logo_default.png">
</p>

# Topic Summary
> Program: PCSX2 v1.6  
> Release Date: 2002
> Requirements:  
> - PCSX2 v1.6 (or lower)
> - SOCOM 2 U.S Navy SEALs NTSC (patch r0001)

I want to help resolve a big issue that will plague anybody who tries to make a trainer for PCSX2 v1.6 and earlier.  
Any patches applied in lower memory regions whether it be external or internal , will be not be applied until the virtual memory table is recompiled.  

A simple example to highlite this problem would involve applying the Render Fix patch for SOCOM 2.  
Writing to the address will show the changed value in both the emulator debug view and cheat engine.

<!-- 

    IMAGES

-->

## Reversing PCSX2 Source
Solving this issue will require dissecting the PCSX2 source code. Originally I found that applying a speedhack patch in PCSX2 settings would trigger any applied patches from my trainer to work. This proved to be a rather interesting fing as it didn't take too much searching in PCSX2 Source to find a function we could utilize. Lets first go over the process of even finding such a function. The PCSX2 source is MASSIVE, even knowing that changing the speed in settings and pressing apply would cause our cheat to finally apply as normal .... There is A LOT happening when you press that "Apply Changes" button. 

**Basic Steps**
> - Download PCSX2 Source Code  
> - Dissect Source Code for possible entry points  
> - Compile PCSX2 from Source  
> - Launch PCSX2 from Visual Studio in Debug Mode  
> - Set set a lot of breakpoints 
Sounds simple enough right?

As mentioned applying patches in settings will also apply our games patches. Another key thing to note that I have forgot to mention is that PNACH files do in fact work, this issue is only for people using non native methods to modify process memory. This includes trainers and CheatEngine. 

This leaves us with 2 areas to dig through. Much better than digging through the entire source code
- PCSX2 PNACH System
- PCSX2 General Settings  

Searching for `PNACH` itself won't turn up much but a search for "patch" will at least give some stuff to filter through (a lot, ignore anything `dispatch()`)  
`PatchesCon` and `PatchesVerboseReset()` both look pretty interesting. Double clicking on either of the two will bring us to where it is declared in whichever file it is housed in.  

`AppCoreThread.cpp`  
It's really hard to contain your excitement when scrolling through this file. We can see above the variable found in our search is some settings that are applied in General Settings window.
If anything it appears we are at least getting close to our objective.
```
> // PatchesCon points to either Console or ConsoleWriter_Null, such that if we're in Devel mode  
> // or the user enabled the devel/verbose console it prints all patching info whenever it's applied,  
> // else it prints the patching info only once - right after boot.  
```
![image](https://i.imgur.com/zXpQR6E.png)![image](https://i.imgur.com/BKBh0u2.png)
<p align="left"> <img src="https://i.imgur.com/zXpQR6E.png"> </p> <p align="right"> <img src="https://i.imgur.com/BKBh0u2.png"> </p>  

## Compiling PCSX2 from Source
Still have a lot more reversing to do, but before go any further it would be a good time to compile PCSX2 from source and start looking at the logs.


<!-- 

    IMAGES

-->


## Finding the Function
The following function is located in file - `iR5900-32.cpp`
```c++
// Original PCSX2 1.6.0 Function
static void recResetEE()
{
    if (eeCpuExecuting)
    {
        eeRecNeedsReset = true;
        return;
    }

    recResetRaw();
}
```
This will do everything required to reset the Emotion Engine and load any patches that have been applied before triggering a recompile.

 {% include youtube.html id="Jd9Rlp59Xkw" %}

## Source Code
The simplest solution is to call the function `recResetEE();` in PCSX2
Here is the AoB for the function: `80 3D ?? ?? ?? ?? ?? 74 0A B0`

```c++
// Define Function
void __cdecl PCSX2RecompileMEM()
{
    typedef void(__cdecl* pFunctionAddress)();
    pFunctionAddress pResetEE = (pFunctionAddress)((moduleBase2 + offsets::recResetEE));
    pResetEE();
}

//  CALL FUNCTION (Recompile Virtual Memory)
if (GetAsyncKeyState(VK_NUMPAD7) & 1)
{
    // patch function requires PCSX2 codes be written in reverse order as shown below
    // This is a function from the GuidedHacking Bible
    // Visit https://www.GuidedHacking.com/ to learn more
    mem::Patch((BYTE*)0x2033CD68, (BYTE*)"\xDB\x00\x00\x10", 4);

    // Recompile Virtual Memory (this will apply our patch)
    PCSX2RecompileMEM();
   
    // Print to the console our changed memory
    printf("RenderFix Value: %X \n", *(uintptr_t*)0x2033CD68);
}
```