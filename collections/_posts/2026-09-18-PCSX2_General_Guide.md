---
title: [PCSX2 - A General Guide for Making Cheats & Trainers]
category: PCSX2
date: 2026-09-18
encrypted_text: true
---

# [PCSX2] A General Guide for Making Cheats & Trainers

[Video demonstration](https://www.youtube.com/watch?v=51EKeoEf_OU)
> PCSX2 is a free and open-source PlayStation 2 (PS2) emulator. Its purpose is to emulate the PS2's hardware, using a combination of MIPS CPU Interpreters, Recompilers and a Virtual Machine which manages hardware states and PS2 system memory.

## OVERVIEW

This post intends to cover PCSX2 and all information provided will be in regards to PCSX2. 
PCSX2 has a variety of versions available, this post will discuss and share methods for the following:

- v1.6 Release
- v2.0 Nightly builds

*PCSX2 v1.5 is referenced in regards to PCSX2dis (a custom solution which combines PCSX2 & PS2dis) but is not a version that should be targeted for making cheats, methods discussed in this post may or may not work for this version of PCSX2.*

Making a trainer for an emulator is not an easy feat to accomplish. Not only do you need to know the basics in creating a trainer for a PC game, you need a very good understanding on how memory is managed for both PC as well as the platform you intend to create cheats for such as type definitions and their sizes.
Some of the challenges you will encounter while trying to create a trainer with PCSX2

- Pointers are hard to understand and navigate
- Certain regions of memory will not react to changes until the virtual memory table is recompiled (understanding this requires you to peep the source code)
- 1.6 is x86 & 2.0 is x64
- 1.6 has static region for EEmem (0x20000000) whereas 2.0 requires a pointer
- Navigating Pointers is even messier in 2.0 (due to x64)
- 2.0 being x64 makes things wicked complicated in regards to memory (i.e pointers and addresses are typically 8bytes but everything for EEmem needs to be converted to 4bytes)

PS2 Memory in PCSX2 terms is called EEmemory. EE stands for Emotion Engine which was the PS2's Central Processing Unit.
PCSX2 v1.6 EEmemory is located at a static address of 0x20000000
PCSX2 v2.0+ EEmemory can only be obtained via exported module. In cheat engine its address is accessible via the following
```text
<moduleName>.EEmem
PCSX2x64-avx2.EEmem
```

## EEMem ( PS2 Game Base Address )

That list mentions "Game Memory" quite a bit so let's take a moment to define it. Accessing & maintaining the target games base address in memory is crucial to the development of a cheat and acts as a reference point for many memory operation to be performed. I breifly mentioned that there was a requirement of obtaining the virtual address of a function located in the Export Address Table (EAT). This address points to a section known as "EEMemory". "EE" is short for Emotion Engine which is the PlayStation 2's CPU and is the name used by the PCSX2 developers for their static pointer, the export however was named "EEMem" and is the string associated with the exported symbol. The virtual address for "EEmem" points to the base address of the target games memory. Anything related to the specific game instance will be here. Things such as world object, player object, game instance and other important game structures and methods. Accessing the exports section of a process is not really a basic procedure due to its complexity but does pose as a great introduction to accessing process memory via structures and pointers outside of typical scans and pointer chains. 

In cheat engine EEMemory is accessible via the following
```text
pcsx2-qt.EEmem
```

Internal C++ DLL EEMemory is accessible via [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
in c++ however things get a bit more complex depending on your attack method be it internal or external. If your application is internal you can call "GetProcAddress" with the name of the export "EEmem" to get a pointer to the export virtual address. These are the easiest methods to obtain access to a games base address. 
```text
// inside dll main ( reference to hModule , this can be passed to a variable as well.)
unsigned __int64 EEMem = GetProcAddress(hModule, "EEmem");
```

External C++ is probably the hardest method of accessing EEMemory. You need to walk the export table until you get a name that matches an input key which in our case would be "EEmem". The process itself is actually quite simple once you understand how the data is structured. Though it is still the most tedious process when compared to other approaches.
```text
//  below is my adaptation of GetProcAddress. Its further transformed to utilize the PCSX2PROCESSINFO64 structure defined in the spoiler below. You really just need the module base address of PCSX2 to get EEMemory address pointer
__i64 PCSX2Memory::GetProcAddressEx(const pcsx2_t& pInfo, const std::string& name, __i64& result)
{
	result = 0;	//	set invalid pointer

	auto dosHeader = Read<IMAGE_DOS_HEADER>(pInfo.uBaseAddress);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	auto ntHeader = Read<IMAGE_NT_HEADERS>(pInfo.uBaseAddress + dosHeader.e_lfanew);
	for (IMAGE_DATA_DIRECTORY& directory : ntHeader.OptionalHeader.DataDirectory)
	{
		__i64 exportRVA = pInfo.uBaseAddress + directory.VirtualAddress;
		if (!exportRVA)
			continue;

		auto exports = Read<IMAGE_EXPORT_DIRECTORY>(exportRVA);
		auto namesRVA = pInfo.uBaseAddress + exports.AddressOfNames;
		auto functionsRVA = pInfo.uBaseAddress + exports.AddressOfFunctions;
		for (int i = 0; i < exports.NumberOfNames; i++)
		{
			auto nameOffset = Read<__i32>(namesRVA + i * sizeof(DWORD));
			auto fnOffset = Read<__i32>(functionsRVA + i * sizeof(DWORD));

			std::string name;
			if (!ReadString(pInfo.uBaseAddress + nameOffset, name))
				continue;

			if (name != name.c_str())	//  Todo: case sensitive
				continue;

			result = Read<__i64>(pInfo.uBaseAddress + fnOffset);
			break;
		}

		if (result)
			break;
	}

	return result;
}
```
<details>
<summary>PCSX2Memory::ResolveProcess Function</summary>

```text
typedef unsigned __int8 __i8;		//	1Byte
typedef unsigned __int16 __i16;		//	2Bytes
typedef unsigned __int32 __i32;		//	4Bytes
typedef unsigned __int64 __i64;		//	8Bytes

struct PCSX2PROCESSINFO64
{
	HANDLE hProc{ INVALID_HANDLE_VALUE };		//	handle to process
	DWORD dwProcID{ 0 };						//	process id
	__i64 uBaseAddress{ 0 };					//	process module base address -> IMAGE_DOS_HEADER
	__i64 uEEmem{ 0 };							//	pcsx2 game module base address
}; typedef PCSX2PROCESSINFO64 pcsx2_t;
bool PCSX2Memory::ResolveProcess(const std::string& pName, pcsx2_t& pInfo)
{
	pInfo = pcsx2_t();

	std::wstring key = std::wstring(pName.begin(), pName.end());
	std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return std::tolower(c); });
	if (!key.size())
		return false;

	///	GET PROCESS ID
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	if (!Process32First(hSnap, &pEntry))
	{
		CloseHandle(hSnap);
		return false;
	}

	bool bFound{ false };
	do
	{
		auto name = std::wstring(pEntry.szExeFile);
		std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {return std::tolower(c); });
		if (name != key)
			continue;

		bFound = true;
		pInfo.dwProcID = pEntry.th32ProcessID;

	} while (Process32Next(hSnap, &pEntry));
	CloseHandle(hSnap);

	if (!bFound || !pInfo.dwProcID)
	{
		pInfo = pcsx2_t();
		return false;
	}

	///	GET PROCESS MODULE BASE
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pInfo.dwProcID);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		pInfo = pcsx2_t();
		return false;
	}

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(me32);
	if (!Module32First(hSnap, &me32))
	{
		pInfo = pcsx2_t();
		CloseHandle(hSnap);
		return false;
	}
	CloseHandle(hSnap);	//	first module is PCSX2

	pInfo.uBaseAddress = (long long)me32.modBaseAddr;	//	module base address

	///	OBTAIN HANDLE TO PROCESS
	pInfo.hProc = OpenProcess(PROCESS_ALL_ACCESS, false, g_pcsx.dwProcID);
	if (pInfo.hProc == INVALID_HANDLE_VALUE)
	{
		pInfo = pcsx2_t();
		return false;
	}

	//	GET EE MEMORY
	return GetProcAddressEx(pInfo, "EEmem", pInfo.uEEmem) > 0;
}
```

</details>

## Finding Pointers and Offsets

I mentioned that creating a trainer for PCSX2 required basic knowledge on making a trainer for PC. It's assumed you also have knowledge on obtaining variables with tools such as Cheat Engine and Reclass. This example uses SOCOM 1 to find the PlayerPosition offset as well as the PlayerPointer.

Search for Player Position. This is the most basic thing you could search for, just search for changed floats.
if you have the correct address -> freezing it results in not being able to move.

Now this is where you will most likely encounter your first problem. (Most Definitely in this situation)
In regards to SOCOM 1 the actual player position that can be edited is a member variable of the CZSealObject class which is pointed to from the CZSeal structure / class. This effectively means you will need a pointer to access this value on a consistent basis. Obtaining a pointer to this can be done with a variety of approaches. The following is the most efficient and simplest method that can be explained.

### PCSX2 1.6

<details>
<summary>Additional details</summary>

- Get an address for the class member in question "212B064C"
- Go to the PCSX2 process window -> Debug -> Open Debug Window
- - You can view the debug view shortcuts by clicking the "?" in the top right
- Click the breakpoint button at the top and input the address without the prefixed 0x2 (012B0E3C instead of 212B0E3C)
- Set a read breakpoint and perform an action in the game so it is triggered
- Analyze the instruction in the debugger to get an idea as to what the offset is and where the base address is

in this example the instruction is as follows
```text
    lwc1    f00,0x1C(s1)
```Essentially this is storing the value at offset 0x1C into register f00
the register in parenthesis will contain the base address for the class variable

The result would be as follows
<u>Base Address</u>: 212B0630
<u>PositionX Offset</u>: 0x1C

You can verify this by putting that address into cheat engine table and adding 0x1C to it (don't forget to prefix the address with 0x2 ie: 212B0630)
212B0630+ 1CC = 212B064C

The final step to this process is searching for the value in PCSX2 using cheat engine. Like with the debugger , you will have to search for the value in raw format. Only pointer and addresses are prefixed with 0x2

<u>search for</u>: 012B0630 (4 byte Hex)
Some Helpful Tips:

- There may be a few each of which you can save.
- The pointer will and should start with "0x20"
- Disregard anything that starts with "PCSX2..."
- The address will not be green (static)

Store all found addresses into your table and restart PCSX2 completely

Manually check which of the saved addresses contains a pointer to the class and its member variable (positionX)

That basically covers how to find a pointer to a class member variable. It may not always be this simple. If you come up with a another solution please share it here
![](https://i.imgur.com/mik5lud.png)

</details>

### PCSX2 v2.0

<details>
<summary>Additional details</summary>

Its effectively the very same process as PCSX2 v1.6 The key difference here is that memory is much different 

in PCSX2 v1.6 our address for CZSealObject->PositionX was 0x212B064C
For this excersise a search via PCSX2 v2.0 resulted in the following address for the same variable 7FF6D11A583C

PCSX2 v2.0 has a pointer to the EEmemory range. Its accessed via an exported module EEmem. You can obtain it by using the following address
```text
PCSX2x64.EEmem
```In this instance EEmem points to the following address: 00007FF6D0000000
Think of this address as the 0x20000000 section in PCSX2 v1.6 except it will change every time you launch PCSX2

So we can take the address we found for our position and subtract it from EEmem to get the RAW PS2 address for our Position

7FF6D11A583C - 00007FF6D0000000 = 0x11A583C;

Now that you have this addres , simply follow the steps outlined for PCSX2 v1.6 to get a pointer to the address
![](https://i.imgur.com/ZU98ER4.png)

</details>

## Recompiling the Virtual Memory Table

There's a lot that goes into this, mainly the discovery aspect. I'm not gonna bother with explaining how all of this was found or the steps involved with reversing such a thing. It's not the point of this tutorial, The point is mainly to get the tools and knowledge out there so that more people start developing trainers for PCSX2 as it can be so rewarding and I believe it can be a great stepping stone to game hacking in general. 

Essentially memory in PCSX2 is accessed in a very weird manner. At some point you might write to memory and realize no change is being made via cheat engine yet the change is being made if you edit the memory in the PCSX2 debugger. For one, noticing this requires a high level of knowledge on what you are trying to achieve. Most people would see that a value change has no effect and move onto the next ... that is REALLY dangerous in terms of hacking PS2 games Because you'll NEVER find the value because you simply ignored it for not being the result. This also gets really confusing as well. For the most part ... this really only effects .text segment functions (in pc hacking terms) meaning you wont really need to mess about with this if you are accessing class variables and just modifying say player health , position and weapon ammo directly. But lets for a second think about how these things are done effectively on PC. We don't leave it at finding the offset right? You get what writes / accesses that address and patch the instruction. THIS is where you will need to recompile the virtual memory table. Because if you patch a function, the change will not be seen by the emulator as the interpreter is using the cached result. 

in PCSX2 source there is a file called "iR5900-32.cpp" within it is a function called recResetEE. If you call this function after applying your byte patch, it will get recompiled and your changes will take effect. This one thing tripped me up for SOOOOOO long
```text
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

## CHEAT ENGINE SCRIPTS

The following are some useful scripts to be used with cheat engine to ease with finding and developing cheats for PCSX2 v2.0.
I have not made any for 1.6 but now that I have made this thread I will make a point to update it with some scripts for that version as well

### PCSX2 v2.0

<details>
<summary>Additional details</summary>

GetEEmem
```text
-- Register PS2mem Symbol --
local PS2mem = getAddress("PCSX2x64.eemem")
PS2mem = readPointer(PS2mem)
registerSymbol("PS2mem", PS2mem, true)
```

ResolveAddress
```text
-- Resolves input RAW PS2 address
-- example input: 0x20440C38
-- example output: 0x440C38
function ResolveAddress(RAW_Address)
    return RAW_Address - 0x20000000
end
```

GetPS2Address
```text
--  Resolves RAW PS2 Address relative to EEMem offset
--  input must be RAW PS2 Offset i.e [ 0x20440C38 ] remove the 0x20
--  Alternatively call Resolve Offset and input everything as RAW PS2 format
function GetPS2Address(offset)
    local base = GetEEMem()
    local result = base + offset     
    return result                    
end
```

GetPS2AddrFromPointer
```text
--  Gets pointer address by reading 4bytes from input
-- returns result + eemem
function GetPS2AddrFromPointer(Pointer)
    local base = GetEEMem()
    local value = readInteger(Pointer)
    local result = base + value       
    return result                      
end
```

GetPS2AddrFromPointerChain
```text
-- Get address by navigating pointer chain
-- input Base Address must be in shorthand RAW PS2 Format, this gets resolved
function GetPS2AddrFromPointerChain(BaseAddress, Offsets)
    local base = GetPS2AddrFromPointer(GetPS2Address(BaseAddress))
    for k,v in pairs(Offsets) do
        base = GetPS2AddrFromPointer(base + v)
    end
    return base
end
```

</details>

## EXAMPLE CHEAT TABLE(S)

### PCSX2 v2.0

Game: Sly Cooper and the Thievius Raccoonus
<details>
<summary>Additional details</summary>

```text

--  PCSX2 Cheat Engine Script Framework  --

PCSX2_VER="pcsx2x64.exe"                --  Module
PCSX2_EEMEM="pcsx2x64.eemem"            --  EEMainMemory Module

-- Pointers
GameStatePointer = 0x2623C0            --  RAW PS2 Offset
WorldStatePointer = 0x2623C4            --  RAW PS2 Offset

-- Classes
local GameState = {
  GameStateFlags  = 0x0,
  nCheckSum      = 0x4,
  Unknown        = 0x8,
  GlobalPlayTimer = 0xC,
  WorldSaves      = 0x10,
  CurrentWorldID  = 0x19d8,
  CurrentLevelID  = 0x19dC,
  LivesCount      = 0x19E0,
  CharmsCount    = 0x19E4,
  CoinsCount      = 0x19E8,
  SettingsFlags  = 0x19EC,
  UnlockedThiefMoves  = 0x19F0,
  UnlockCutscenes    = 0x19F4,
  GameCompletionFlags = 0x19F8,
  LastThiefMove      = 0x19FC
}

local WorldState = {
  LevelSaves    = 0x0,
  KeysCount      = 0x438,
  VaultsCount    = 0x43C,
  MTSCount      = 0x440,
  WorldPlayTimer = 0x444,
  WorldStateFlags = 0x448
}

-- Establish Window Title
TITLE="PCSX2::SlyCooper(v1.0.0)"
MainForm.Caption = string.format('%s - Sly Cooper Modding Community', TITLE)

-- Remove Scan Panel
MainForm.Panel5.visible = false

-- Set Dark Mode
GetAddressList().Control[0].BackgroundColor=0x101010

-- Get Process Path
function GetEXEFilePath(addr,pid)
    local mods=enumModules(pid)
    for k,v in pairs(mods) do
        if v.Address==addr then
          return v.PathToFile
        end
    end
end

-- Attach Process
function AttachProcess(name)
  if not (openProcess(name) and readInteger(name))then
      registerSymbol(name,true)
  end

  if not getOpenedProcessID() then
      messageDialog('PCSX2 2.0 Process Not Found.',1)
      error('PCSX2 NOT RUNNING')
  end

  local FilePath=GetEXEFilePath(getAddressSafe(name),getOpenedProcessID())
  if not FilePath then
    messageDialog("WRONG PROCESS - PCSX2 ERROR",0)
    error("Process not found.")
  end
end

--  Gets EEMem Address
function GetEEMem()
    return readPointer(getAddress(PCSX2_EEMEM))
end

--  Resolves RAW PS2 Address relative to EEMem offset
--  input must be RAW PS2 Offset i.e [ 0x20440C38 ] remove the 0x20
--  Alternatively call Resolve Offset and input everything as RAW PS2 format
function GetPS2Address(offset)
    local base = GetEEMem()          --  EEmem Address
    local result = base + offset
    return result
end

--  Gets pointer address by reading 4bytes from input
-- returns result + eemem
function GetPS2AddrFromPointer(Pointer)
    local base = GetEEMem()          --  EEmem Address
    local value = readInteger(Pointer)    --  EEmem Offset
    local result = base + value
    return result
end

-- Get address by navigating pointer chain
-- input Base Address must be in shorthand RAW PS2 Format, this gets resolved
function GetPS2AddrFromPointerChain(BaseAddress, Offsets)
    local base = GetPS2AddrFromPointer(GetPS2Address(BaseAddress))
    for k,v in pairs(Offsets) do
        base = GetPS2AddrFromPointer(base + v)
    end
    return base
end

-- Attach Cheat Engine to PCSX2 Process
AttachProcess(PCSX2_VER)

-- Get PCSX2 Module
local dwGameBase = getAddress(PCSX2_VER)

-- Get EEMem
local EEmem = getAddress(PCSX2_EEMEM)
local EEModule = GetEEMem()

-- Get GameState Pointer
local GameStateBase = GetPS2AddrFromPointer(GetPS2Address(GameStatePointer))
for k,v in pairs(GameState) do
    registerSymbol(tostring(k), GameStateBase + v)
end
registerSymbol("GameState", GameStateBase)

local WorldStateBase = GetPS2AddrFromPointer(GetPS2Address(WorldStatePointer))
for k,v in pairs(WorldState) do
    registerSymbol(tostring(k), WorldStateBase + v)
end
registerSymbol("WorldState", WorldStateBase)
registerSymbol("dwGameBase", dwGameBase, true)
registerSymbol("EEmem", EEmem, true)
registerSymbol("PS2Mem", EEModule, true)
```

</details>

## Structs & Functions

The following methods are for Internal C++ usage. You can adapt these methods as you see fit. All methods will be for **PCSX2 v2.0**

<details>
<summary>INTERNAL HELPERS</summary>

**ModuleBase, EEMemPointer, EEMemBase **
Without the following , it will be impossible to access game memory.

- **dwGameBase** is the ModuleBase for PCSX2 Process
- **dwEEMem** is the EEmemPointer. It points to the EEmodule
- **BasePS2MemorySpace** is the EEmemModule. This is essentially the base address for the emulated game.

```text
static uintptr_t dwGameBase = (uintptr_t)GetModuleHandle(g_ModuleName);    
static uintptr_t dwEEMem = (uintptr_t)GetProcAddress(g_hModule, "EEmem"); NOTE: g_hModule is initialized upon dll injection. Passing hModule to g_hModule.
static uintptr_t BasePS2MemorySpace = *(uintptr_t*)dwEEMem;
```

### Memory Helpers

/// EXAMPLE:
/// - Original RAW       : 2048D548  
/// - Shortened RAW   : 0x48D548
/// - Base Memory      : 7FF660000000
/// - Result                : 7FF660000000 + 0x48D548 = 7FF66048D548
**GetAddress**
Converts shortened RAW PS2 format address to x64 address
```text
uintptr_t GetAddr(unsigned int RAW_PS2_OFFSET)
{
	return (BasePS2MemorySpace + RAW_PS2_OFFSET);
}
```

**GetClassPointer**
```text
/// <summary>
/// Assigns Shortened RAW PS2 Format Code to Class Pointer
/// Note: Must be a base address
/// </summary>
/// <returns>ClassPointer</returns>
/// - CPlayer
/// - CCamera
uintptr_t GetClassPtr(unsigned int RAW_PS2_OFFSET)
{
	return *(int32_t*)(RAW_PS2_OFFSET + BasePS2MemorySpace) + BasePS2MemorySpace;
}
```

**ResolvePointerChain**
```text
/// <summary>
/// Resolves Pointer Chain from input Shorthand RAW PS2 Format Address
/// </summary>
/// <param name="RAW_PS2_OFFSET"></param>
/// <param name="offsets"></param>
/// <returns></returns>
uintptr_t ResolvePtrChain(unsigned int RAW_PS2_OFFSET, std::vector<unsigned int> offsets = {})
{
	//  --
	uintptr_t addr = (*(int32_t*)GetAddr(RAW_PS2_OFFSET)) + BasePS2MemorySpace;
	if (offsets.empty())
		return addr;

	// --- untested (possibly not needed anyways, should work)
	// GetClassPtr and relevent functions within each class will make this useless
	for (int i = 0; i < offsets.size(); i++)
	{
		addr = *(int32_t*)addr;
		addr += (offsets[i] + BasePS2MemorySpace);
	}
	return addr;
}
```

The following functions take the full address i.e [7FF7xxxxxxxx]
This means you should resolve any offsets prior to using this function.
PS2BaseMemorySpace + Offset (much like you would normally do ModuleBase + offset)
Alternatively its advised to use the GetAddress function. Which takes a shorthand PS2 offset , applies it to the EEmemModuleBase and returns the sum of the 2.
NOTE: Only reads / writes the last 4 bytes
/// USING FRAMERATE AS AN EXAMPLE
//0x7FF6B048CF60 0000001E0000001E // 8 Bytes
//0x7FF6B048CF60 0000001E // 4 Bytes

**READ MEMORY**
EXAMPLE: int VALUE = PS2Read<int>(PS2BaseMemorySpace + 0x44D648);
this would read the value stored at the input address.
```text
template<typename T> inline T PS2Read(uintptr_t Address)
{
	unsigned int format = *(int32_t*)Address;
	T A{};
	A = (T)format;
	return A;
}
```

**WriteMemory**
EXAMPLE: PS2Write<int>(PS2BaseMemorySpace + 0x44D648, NULL);
this would write 00000000 to address located at PS2BaseMemorySpace + 0x44D648
```text
template<typename T> inline void PS2Write(uintptr_t Address, T Patch)
{
	*(int32_t*)Address = Patch;
}
```

</details>

## Expanding Beyond Basic Memory Access

As my research continued, I came up with newer methods for working with games inside PCSX2. The information on this subject is already sparse, so I have kept those discoveries together here instead of splitting them into unrelated posts.

## Hooking Render API

PCSX2 utilizes just about every rendering api available and can be a really good starting point for people trying to understand the concept of hooking a render api and drawing their own UI. 
PCSX2 Supports the following

- DirectX11
- DirectX12
- OpenGL
- Metal
- Vulkan

How does PCSX2 maintain instances you might ask? Well its rather simple. They have a base class that they have named "GSDevice" and every rendering api builds off of this virtual method as derived classes. Think GSDevice11 for Dx11. 
Basically this class will initialize an instance of DX11 , present a window and render everything using DirectX11. You can hook it as you normally would Get a handle to d3d11 and get the virtual method for present. 

**Example of hooking D3D11 Present using the process's GSDevice class instance:**
```text
// Obtain instance of GSDevice
CGlobals::g_gs_device = reinterpret_cast<GSDevice*>(*(__int64*)(Memory::GetAddr(gDevice)));

if (CGlobals::g_gs_device->GetRenderAPI == RenderAPI::D3D11)
{
     auto d3d11 = reinterpret_cast<GSDevice11*>(CGlobals::g_gs_device);
     if (d3d11)
     {
          auto pSwapChain = d3d11->GetSwapChain();
          if (pSwapChain)
                  PlayStation2::hkVFunction(pSwapChain, 8, oIDXGISwapChainPresent, hkPresent);
     }
}
```

## Tracking InGame Register Variables & Manipulating Function Execution

The following method is a bit more advanced and will require a bit of forward thinking. PCSX2 is a interpreter / recompiler. It reads MIPS machine code instructions and outputs it to x86 machine code and caches it for execution. One might find themselves wondering how to access a function in regards to Calling and hooking methods. Unfortunately things are a bit fickle here. There is no `minhook` library to accomplish such a feat and there really arent many great game hackers messing with PCSX2 to have formulated a desire / need to create a library for such a practice, its a shame but I think the path I am on now is how these things actually come to be. Anyways , the PlayStation 2 has 2 CPUS. One for handling IO and the other for handling game logic.

- [R5900](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/R5900.h) is the CPU responsible for game logic [ EE ]
- [R3000A](https://github.com/PCSX2/pcsx2/blob/master/pcsx2/R3000A.h)  is the CPU responsible input output [ IOP ]

Each of the headers above will be much better at explaining HOW everything works than I could ever hope to dream of doing. But for all intents and purposes you will need the following structures if you have any hope of obtaining information on functions as they are executed. You will have the executing address and structures available to readout register variables in correspondence to the currently instruction being recompiled. With this information you could change anything in a game as its being run without even having code executing in the game. Think, you dont need to write a code cove, you dont need to change bytes at an address so that a memory scanner can determine that youve changed memory. No , everything from this point will be done directly with register variables as the instruction is being executed.

### Functions of note

- [ [iR5900.cpp](https://github.com/PCSX2/pcsx2/blob/b5472c1b51fd4db50be1f501e3832459989d6e75/pcsx2/x86/ix86-32/iR5900.cpp#L1660-L1938) ] recompileNextInstruction
- [ [iR3000A.cpp](https://github.com/PCSX2/pcsx2/blob/b5472c1b51fd4db50be1f501e3832459989d6e75/pcsx2/x86/iR3000A.cpp#L1404-L1478) ] psxRecompileNextInstruction

### Variables of note

- [cpuRegs](https://github.com/PCSX2/pcsx2/blob/b5472c1b51fd4db50be1f501e3832459989d6e75/pcsx2/R5900.h#L205)
- [psxRegs](https://github.com/PCSX2/pcsx2/blob/b5472c1b51fd4db50be1f501e3832459989d6e75/pcsx2/R3000A.h#L120)

in both functions it can be noted that each structure contains a variable 'pc' which is used to determine current instruction execution, it is then iterated after being read. We can use this variable in the structure in our own module to determine if our method / instruction is being accessed and if so modify register variables accordingly.

```text
///  Get Debug Registers
PlayStation2::PCSX2::o_cpuRegs = 0x0;
PlayStation2::PCSX2::g_cpuRegs = reinterpret_cast<PlayStation2::cpuRegisters*>((PlayStation2::Memory::GetAddr(PlayStation2::PCSX2::o_cpuRegs) - 0x2AC));    //  [0x2AC is g_cpuRegs.code] The offset for cpuRegs found in recompileNextInstruction is displaced to the code offset in the structure

PlayStation2::PCSX2::o_psxRegs = 0x0;
PlayStation2::PCSX2::g_psxRegs = reinterpret_cast<PlayStation2::psxRegisters*>((PlayStation2::Memory::GetAddr(PlayStation2::PCSX2::o_psxRegs) - 0x20C));   //    similar to cpuRegs, the found offset is displaced and must be brought back to origin to access the data.

/// Reset Recompiler To track execution
PlayStation2::PCSX2::o_recResetEE = 0x0;    
PlayStation2::PCSX2::ResetEE();             //  Reset EE so that we can re/capture events

//  Capture EE Function Compilation
if (PlayStation2::PCSX2::g_cpuRegs->pc == fn_start)
{

	//  Capture Register Data
	const auto pc = PCSX2::g_cpuRegs->pc;           //  program counter
	const auto code = PCSX2::g_cpuRegs->code;       //  ~
	const auto GPR = PCSX2::g_cpuRegs->GPR;         //  registers

	//  Log Data
	Console::cLogMsg("[+] PCSX2::PS2::EE::fnName()\npc:\t%d\ncode:\t%d\nGPR.sp:\t%d\n\n",
		EConsoleColors::yellow,
		pc,                         //  
		code,                       //  
		GPR.sp.n[0]                 //  
	);
}

//  Capture IOP Function Compilation
if (PlayStation2::PCSX2::g_psxRegs->pc == fn_start)
{
	using namespace PlayStation2;

	//  Capture Register Data
	const auto pc = PCSX2::g_psxRegs->pc;           //  program counter
	const auto code = PCSX2::g_psxRegs->code;       //  ~
	const auto GPR = PCSX2::g_psxRegs->GPR;         //  registers

	Console::cLogMsg("[+] PCSX2::PS2::IOP::fnName()\npc:\t%d\ncode:\t%d\nGPR.sp:\t%d\n\n", 
		EConsoleColors::yellow,
		pc,                         //  
		code,                       //  
		GPR.sp                      //  
	);
}
```

**Function and class-variable AOBs:**
<details>
<summary>Additional details</summary>

```text
static unsigned int o_gs_device;                                                //  global pointer to GSDevice  -> PCSX2 v1.7.5617: 0x3FA2728
static unsigned int o_GSDevice_GetRenderAPI;                                    //  offset to function  //  GSDevice::vfIndex [9]
typedef RenderAPI(__fastcall* GSDevice_GetRenderAPI_stub)(GSDevice*);           //  Returns the graphics API used by this device.
typedef __int64(__fastcall* GSUpdateDisplayWindow_stub)();                      //  [ Nightly AOB: 48 83 EC 48 48 8B 0D ? ? ? ? 48 ] [ Soource AOB: 48 83 EC 48 48 8B 0D ? ? ? ? 48 8B ]
typedef void(__fastcall* psxRecompileNextInstruction_stub)(bool, bool);         //  [ Nightly AOB: E8 ? ? ? ? 8B 05 ? ? ? ? 8B 0D ? ? ? ? 85 ]  [ Source AOB: E8 ? ? ? ? 8B 15 ? ? ? ? 85 D2 75 ]
typedef void(__fastcall* recompileNextInstruction_stub)(bool, bool);            //  [ Nightly AOB: E8 ? ? ? ? C7 44 24 ? ? ? ? ? 49 ]  [ Source AOB: ~ ] [ string: xref "Applying Dynamic Patch to address 0x%08X" ]
typedef void(__fastcall* recResetEE_stub)();                                    //  [ Nightly AOB: 80 3D ?? ?? ?? ?? ?? 75 30 C6 05 ?? ?? ?? ?? ?? C6 ]  [ Source AOB: 80 3D ? ? ? ? ? 74 3D 80 ]
static unsigned int o_cpuRegs;      											//  offset  ->  PCSX2 v1.7.5617: 0x2EA8F2C
static cpuRegisters* g_cpuRegs;     											//  iR5900
static __int32 g_cpupc;             											//  offset  ->  PCSX2 v1.7.5617: 0      //  Todo:have not determined a method for obtaining
static unsigned int o_psxRegs;      											//  offset  ->  PCSX2 v1.7.5617: 0x2EA809C
static psxRegisters* g_psxRegs;     											//  iR3000A
static __int32 g_psxpc;             											//  offset  ->  PCSX2 v1.7.5617: 0      //  Todo:have not determined a method for obtaining
```

</details>

## Accessing PlayStation 2 ScratchPad RAM Through PCSX2

While digging deeper into SOCOM on PCSX2, I was specifically trying to refine a better world-to-screen matrix. Along the way I stumbled onto something pretty interesting: the PlayStation 2’s 16KB ScratchPad RAM being accessed directly through emulated memory.

### What is the ScratchPad?

The Emotion Engine (EE) has a small 16KB block of ultra-fast memory called the ScratchPad. a lot of games utilize this for transformations and matrix math.

- Think of it as a workspace for temporary values, often math heavy stuff.
- It’s used to store things that need fast DMA access or must be shared between processes without hitting main memory.

While reversing, I found some pseudocode that copies a matrix from the camera class (CZCamera*).
That second line is the interesting one as it’s pulling a matrix from CZCamera* + 0x3C0 + 0x20.
```text
CZSealBody::GetHeadParams((_DWORD *)v13, (int)v57, (int)v58);	//	gets the head bone world tm
sceVu0CopyMatrix((int)v53, *(_DWORD *)(*(_DWORD *)(zdb::CWorld::m_world + 0xC0) + 0x3C0) + 0x20);	// copies a matrix from CCamera* @ 0x3c0 + 0x20
```

![](https://i.imgur.com/qCGc7vn.png)

**Full code block:**
<details>
<summary>Additional details</summary>

```text
v29 = sub_17B190(&x__data_CEntity_m_List);
result = sub_17B170(v54, v29);
v54[2] = v54[0];
v51 = v54[0];
if ( SLODWORD(v48) == SLODWORD(v54[0]) || v10 >= 15 )
  break;
v11 = *(LODWORD(v48) + 8);
v12 = 0LL;
if ( *(LODWORD(v48) + 8) && *(v11 + 16) == 2LL )
  v12 = 1LL;
if ( !v12 )
  v11 = 0LL;
if ( v11 )
{
  if ( x__CEntity::GetNode(v11) )
  {
	if ( sub_2544C0(v11) < 5.0 )
	{
	  Node = x__CEntity::GetNode(v11);
	  if ( x__zdb::CNode::Rendered(Node) )
	  {
		if ( x__ftsGetPlayer() != v11
		  && ((*(v11 + 196) & 1LL) != 0) == ((*(x__ftsGetPlayer() + 196) & 1LL) != 0)
		  && (*(v11 + 196) & 0x20000) == 0 )
		{
		  x__CZSealBody::GetHeadParams(v11, v46, v47);
		  sceVu0CopyMatrix(v42, *(*(*(v6 - 28200) + 0xC0) + 0x3C0) + 0x20);
		  _$V1 = v42;
		  v15 = v44;
		  v43[3] = 1.0;
		  _$A1 = v43;
		  LODWORD(v17) = 1;
		  v43[2] = v46[2];
		  v43[0] = v46[0];
		  v43[1] = v46[1] + 3.0;
		  __asm
		  {
			lqc2    $4, 0($v1)
			lqc2    $5, 0x10($v1)
			lqc2    $6, 0x20($v1)
			lqc2    $7, 0x30($v1)
		  }
		  do
		  {
			__asm
			{
			  lqc2    $8, 0($a1)
			  cop2    0x1E821BC
			  cop2    0x1E828BD
			  cop2    0x1E830BE
			  cop2    0x1E83A4B
			  sqc2    $9, 0($a0)
			}
			v17 = v17 - 1;
			_$A1 += 4;
			v15 += 4;
		  }
		  while ( v17 );
		  if ( v45 > 0.000099999997 )
		  {
			v18 = 1.0 / v45;
			(*(*(a1 + 140 * v10 + 40) + 96))(a1 + 140 * v10 + 28, *(v11 + 20));
			x__C2DString::UpdatePos(a1 + 140 * v10 + 28);
			v19 = v44[1] * v18;
			v20 = *(140 * v10 + a1 + 96) / 2.0;
			v21 = (((v44[0] * v18) + 320.0) - 2048.0) - v20;
			v22 = (v19 + 224.0) - 2048.0;
			if ( v21 >= 600.0 || (v23 = *(a1 + 2128), v22 >= (448.0 - v23)) || v21 <= 0.0 || v22 <= v23 )
			{
			  (*(*(a1 + 140 * v10 + 40) + 96))(a1 + 140 * v10 + 28, dword_47DB78);
			}
			else
			{
			  if ( (v21 + v20) > 600.0 )
				v21 = 600.0 - v20;
			  v24 = *(140 * v10 + a1 + 96) / 2.0;
			  if ( (v21 - v24) < 0.0 )
				v21 = v24;
			  for ( i = 0LL; i < v10; i = i + 1 )
			  {
				if ( x__WordIntersectionTest_(
					   (v21 - 10.0),
					   (v22 - 10.0),
					   ((v21 + *(140 * v10 + a1 + 96)) + 10.0),
					   ((v22 + (*(*(140 * v10 + a1 + 56) + 28) - *(*(140 * v10 + a1 + 56) + 24))) + 10.0),
					   a1 + 140 * i + 28) )
				{
				  LODWORD(i) = -1;
				  v22 = v22 + 5.0;
				}
			  }
			  if ( (*(v11 + 221) & 8) == 0 )
				sub_2544C0(v11);
			  (*(*(a1 + 140 * v10 + 40) + 36))(a1 + 140 * v10 + 28);
			  v26 = (140 * v10 + a1);
			  v26[40] = 16 * v21;
			  v26[41] = 16 * v27;
			  (*(v26[10] + 28))((v26 + 7));
			  v10 = v10 + 1;
			}
		  }
		}
	  }
	}
  }
}
```

</details>

![pointer at CZCamera* + 0x3C0](https://i.imgur.com/x2uNRCr.png)

When I followed the pointer in PCSX2’s debugger, it didn’t land in the usual EE Main Memory range. Instead, it led me straight into the ScratchPad RAM (SPRAM). This section of memory however was not immediately available to me in my own toolset as obtaining reference to scratch pad through the emulation layer proved to be a bit more difficult. Memory is static on true PlayStation 2 hardware as has been discussed in earlier posts with EE having a static offset of 0x20000000. ScratchPad RAM also had a static address. When I tried following the pointer in reclass, it didn’t land in the usual EE Main Memory range. Instead, it led me straight to invalid memory. 

anywho . . . this means the game is copying camera matrices directly into ScratchPad but I would need to come up with a way of accessing that memory range ( typically resides at 0x70000000 on a retail PlayStation 2 ) which is emulated in PCSX2. In this example the game is referencing "0x70003E60" as the pointer into scratch pad memory which would be 0x3E60 from that base address of 0x70000000. It's immediately obvious that in PCSX2 ScratchPad RAM isn’t mapped at 0x70000000 directly. Digging through PCSX2 source code it becomes apparent WHERE they put it and it becomes trivial at that point to obtain its reference from PCSX2. it’s laid out inside the EEVirtualMemory struct alongside EE Main RAM, Extra RAM, and ROMs. That means you need to offset into emulated memory rather than using the raw PS2 address.

See the following struct from pcsx2 source code

<https://github.com/PCSX2/pcsx2/blob/47931a06890ae7ee70f7e3019ad1bdcba8a07c32/pcsx2/MemoryTypes.h#L32-L48>
```text
struct EEVM_MemoryAllocMess
{
	u8 Main[Ps2MemSize::MainRam];         // Main memory (hard-wired to 32MB)
	u8 ExtraMemory[Ps2MemSize::ExtraRam]; // Extra memory (32MB up to 128MB => 96MB).
	u8 Scratch[Ps2MemSize::Scratch];      // Scratchpad!
	u8 ROM[Ps2MemSize::Rom];              // Boot rom (4MB)
	u8 ROM1[Ps2MemSize::Rom1];            // DVD player (4MB)
	u8 ROM2[Ps2MemSize::Rom2];            // Chinese extensions

	// Two 1 megabyte (max DMA) buffers for reading and writing to high memory (>32MB).
	// Such accesses are not documented as causing bus errors but as the memory does
	// not exist, reads should continue to return 0 and writes should be discarded.
	// Probably.

	u8 ZeroRead[_1mb];
	u8 ZeroWrite[_1mb];
};
```

with this information it was pretty easy to come up with a solution to obtain reference of the scratchpad base and so I wrote a little helper function to cleanly grab the base of ScratchPad in emulated space:

```text
__int64 PS2Memory::GetScratchPadBase() 
{ 
    return Memory::BasePS2MemorySpace + 
           offsetof(EEVirtualMemory, EEVirtualMemory::Scratch); 
}
```

Finally , we have our result matrix that tripped me up for a few hours on my sunday evening. 
![memory view of the matrix being copied](https://i.imgur.com/Gkd3esy.png)

in summary, with PCSX2 , ScratchPad is just another buffer chunk in the big emulated EE memory blob and not at the static offset of 0x70000000. I hope this proves useful to somebody sometime in the future. Currently it does seem that I am going at this alone but regardless ... I deem it necessary to share any and all my findings for those that may be trying to resolve the same problems I find myself facing.

Last but not least ... here is the full function i use in SOCOM to get the Camera View Matrix via scratchpad memory
```text
bool CWorld::GetViewMatrix(Mat4x4* out)
{
	/* sceVu0CopyMatrix((int)v53, *(_DWORD *)(*(_DWORD *)(zdb::CWorld::m_world + 0xC0) + 0x3C0) + 0x20); */

	/* validate camera */
	if (!this->pCamera)
		return false;

	/* get camera */
	CZCamera* pCamera = (CZCamera*)PS2Memory::GetAddr(this->pCamera);
	if (!pCamera)
		return false;

	/* get ScratchPad Offset */
	const auto& offset = pCamera->GetViewMtxHash();
	if (offset <= 0 || offset >= ((1024 * 1) * 16))
		return false;

	/* read view matrix head from scratchpad */
	const auto& mtx_base = PS2Memory::GetScratchPadBase() + offset;
	if (mtx_base == offset)
		return false;

	/* copy matrix */
	*out = *reinterpret_cast<Mat4x4*>(mtx_base + 0x20);

	return true;
}
```