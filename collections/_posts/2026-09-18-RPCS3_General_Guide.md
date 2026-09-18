---
title: [RPCS3 - A General Guide for Making Cheats & Trainers]
category: RPCS3
date: 2026-09-18
encrypted_text: true
---

# RPCS3: A General Guide for Making Cheats & Trainers

> RPCS3 is a free and open-source PlayStation 3 (PS3) emulator. Its purpose is to emulate the PS3's hardware, using a combination of Cell CPU Interpreters, Recompilers and a Virtual Machine which manages hardware states and PS3 system memory.

## OVERVIEW

RPCS3 has a variety of versions available, this post will discuss and share methods for the most up to date release therefore if any methods change this post will be updated to reflect current methods (old methods will be archived at the bottom in a spoiler tag).

Making a trainer for an emulator can be quite the difficult task. You need to know the basics in creating a trainer for a PC game, you need a decent understanding on how memory is managed for both PC as well as the platform you intend to create cheats for ( Power PC in this case ) such as instruction set, memory alignment , basic type definitions. Additionally , understanding the header format for dumping / enumerating modules is kind of necessary and typically won't be able to leverage libraries like WINAPI so things need to be done manually. Below are some of the challenges you will encounter while trying to create a trainer targeting an RPCS3 title.

- Pointers are hard to understand and navigate ( they won't immediately stand out until you've dealt with them enough )
- Memory is laid out differently from PC memory (big endian vs little endian)
- Disassembly with cheat engine is pointless for game memory in regards to breakpoints and finding what accesses an address
- Disassembly with IDA or Ghidra is rough in that you'll probably need to acquire special plugins to decompile the special instruction set. Also understanding what the "exe" is and finding the point of entry is not as straightforward as with a windows executable.

For this guide I will be demonstrating all memory and reversal techniques with "Demon's Souls" `BLUS30443` 1.0.0. You may use another version of the game and try to follow along or another game. The techniques may differ game to game , the fun part with game hacking is using creativity to meet your goal. 

![](https://i.imgur.com/YOw3eZE.png)
*g_base_addr*

![](https://i.imgur.com/TPtlMww.png)
*g_sudo_addr*

## VM & SUDO ( PS3 Game Base Address )

Obtaining access to the game's base address in RPCS3 is similar to how you would do it in PCSX2. The main difference is that the base address is not exported and will change with each version / update to the emulator ( the current method may even become obsolete ). The most straightforward method to obtain the base address is to throw RPCS3 into IDA and search for the qwords directly. RPCS3 is open source so we can easily determine where the VM is defined and then use that information to track where it gets initialized. Above is the code snippet from RPCS3's source code that defines and initializes the VM namespace. The base address is defined as g_base_addr and the sudo address is defined as g_sudo_addr. The sudo address is a mirror of the base address and is used to access the game's memory in a more controlled manner. searching for "Failed to reserve vm memory" in IDA will lead you to the function that initializes the VM. From there you can trace back to the base address and sudo address. Below are some signatures to help you find the base address in IDA but these will probably break in the future as the emulator evolves.

PS3 Memory in RPCS3 terms is called g_base_addr & g_sudo_addr inside of the VM namespace. Demonstrated below is RPCS3 source code for defining and declaring the member variables we will be using for accessing game memory.
```c
// VM namespace definitions => vm.h
extern u8* const g_base_addr;
extern u8* const g_sudo_addr;

/// initialization => vm.cpp
// Emulated virtual memory
u8* const g_base_addr = memory_reserve_4GiB(reinterpret_cast<void*>(0x2'0000'0000), 0x2'0000'0000, true);

// Unprotected virtual memory mirror
u8* const g_sudo_addr = g_base_addr + 0x1'0000'0000;

// 
static u8* memory_reserve_4GiB(void* _addr, u64 size = 0x100000000, bool is_memory_mapping = false)
{
	for (u64 addr = reinterpret_cast<u64>(_addr) + 0x100000000; addr < 0x8000'0000'0000; addr += 0x100000000)
	{
		if (auto ptr = utils::memory_reserve(size, reinterpret_cast<void*>(addr), is_memory_mapping))
		{
			return static_cast<u8*>(ptr);
		}
	}

	fmt::throw_exception("Failed to reserve vm memory");
}
```

```text
// .text:00000000006543E0 48 2B 15 91 96 74 03                                            sub     rdx, cs:vm__g_base_addr
// 48 2B 15 ? ? ? ? 48 B8 

// .text:0000000000635938 48 8B 05 C9 84 76 03                                            mov     rax, cs:vm__g_sudo_addr
// 48 8B 05 ? ? ? ? 39 0C 02 75 ? 49 8B 4E ? 48 8B D3
```

```cpp
struct RPCS3PROCESSINFO64
{
	HANDLE hProc{ INVALID_HANDLE_VALUE };		//	handle to process
    HMODULE hModule{ nullptr };					//	handle to module
	DWORD dwProcID{ 0 };						//	process id
	__int64 uBaseAddress{ 0 };					//	process module base address -> IMAGE_DOS_HEADER
    __int64 vmBaseAddress{ 0 };					//	rpcs3 game module base address -> IMAGE_ELF64_HEADER
    __int64 vmSudoAddress{ 0 };					//	rpcs3 game module sudo address
}; typedef RPCS3PROCESSINFO64 rpcs3_t;
bool PS3Memory::ResolveProcess(OUT rpcs3_t& pInfo)
{
	pInfo = rpcs3_t(); // clear container

    pInfo.hProc = GetCurrentProcess();
    pInfo.hModule = GetModuleHandle(0);
    pInfo.dwProcID = GetCurrentProcessId();
    pInfo.uBaseAddress = reinterpret_cast<__int64>(pInfo.hModule);
    pInfo.vmBaseAddress = GetBaseVM();
    pInfo.vmSudoAddress = GetBaseSUDO();
}

u64_t PS3Memory::GetBaseVM(bool bHeader)
{
	/*
		.text:00000000006543E0 48 2B 15 91 96 74 03                                            sub     rdx, cs:vm__g_base_addr
	*/
	static u64_t g_base_addr = 0;
	if (!g_base_addr)
	{
		g_base_addr = Memory::FindPattern("48 2B 15 ? ? ? ? 48 B8", 0, 7, 3, &g_base_addr);
		if (g_base_addr > 0)
			g_base_addr = *(u64_t*)g_base_addr;
	}

	return bHeader ? g_base_addr + ELF_HEADER : g_base_addr; // ".ELF"
}

u64_t PS3Memory::GetBaseSUDO(bool bHeader)
{
	/*
		.text:0000000000635938 48 8B 05 C9 84 76 03                                            mov     rax, cs:vm__g_sudo_addr
	*/
	static u64_t g_sudo_addr = 0;
	if (!g_sudo_addr)
	{
		g_sudo_addr = Memory::FindPattern("48 8B 05 ? ? ? ? 39 0C 02 75 ? 49 8B 4E ? 48 8B D3", 0, 7, 3, &g_sudo_addr);
		if (g_sudo_addr > 0)
			g_sudo_addr = *(u64_t*)g_sudo_addr;
	}

	return bHeader ? g_sudo_addr + ELF_HEADER : g_sudo_addr; // ".ELF"
}
```

![](https://i.imgur.com/bFnJL3T.png)
*little endian*

![](https://i.imgur.com/cMKf073.png)
*big endian*

## Byte Endianness

The PS3 uses big-endian memory layout, which means that the most significant byte is stored at the lowest address. This is different from the little-endian memory layout used by most modern PCs. When working with memory in RPCS3, you need to be aware of this difference and convert between big-endian and little-endian formats as necessary. Windows api offers a few methods to easily byte swap values. For example, _byteswap_ushort, _byteswap_ulong, and _byteswap_uint64 can be used to convert between big-endian and little-endian formats.

Observe the screenshots above for a moment. The address and bytes remain the same however depending on how the bytes are interpreted . . the value is very much different. What we can take notice in is the direction in which the bytes are taken. When read from left to right the value is 0x539 but when read from right to left the value is 0x39050000. This makes it very hard for both analysis as well as using traditional tools for scanning as they are made to interpret bytes in a completely different direction. Below I have included some basic methods for reading 2, 4 and 8 byte sizes however reading structures is an entirely different beast as I will demonstrate below when parsing the ELF header of a game.
```cpp
inline u16_t PS3Memory::ReadShort(const u64_t& addr) 
{ 
	return _byteswap_ushort(Memory::ReadMemoryEx<u16_t>(addr)); 
}

inline u32_t PS3Memory::ReadLong(const u64_t& addr) 
{ 
	return _byteswap_ulong(Memory::ReadMemoryEx<u32_t>(addr)); 
}

inline u64_t PS3Memory::ReadU64(const u64_t& addr) 
{ 
	return _byteswap_uint64(Memory::ReadMemoryEx<u64_t>(addr)); 
}

inline bool PS3Memory::WriteShort(const u64_t& addr, const u16_t& v)
{
	Memory::WriteMemoryEx<u16_t>(addr, _byteswap_ushort(v));

	return ReadShort(addr) == v;
}

inline bool PS3Memory::WriteLong(const u64_t& addr, const u32_t& v)
{
	Memory::WriteMemoryEx<u32_t>(addr, _byteswap_ulong(v));

	return ReadLong(addr) == v;
}

inline bool PS3Memory::WriteU64(const u64_t& addr, const u64_t& v)
{
	Memory::WriteMemoryEx<u64_t>(addr, _byteswap_uint64(v));

	return ReadU64(addr) == v;
}
```

![](https://i.imgur.com/D1lslxH.png)
*ELF Header*

![](https://i.imgur.com/8I472I7.png)
*ELF Program Headers*

![](https://i.imgur.com/lxS0nOo.png)
*ELF Section Headers (not accurately defined , more on this later)*

![](https://i.imgur.com/7qiutyA.png)
*ELF Section Names Array*

![](https://i.imgur.com/N8JXfJU.png)
*Example Section Name*

## ELF Header Parsing

This is a bit more complex both in that we need to define special structures as well as uncover special flag types and their values. For the most part the PS3 games header format follows the linux header format and we can take some structs directly from it , the difference I am noticing is in the section headers ( i am still reversing this aspect myself unfortunately ). Enumerating the program headers is enough to get a good dump for now but I will update this to finish 
```cpp
enum ElfSectionType : unsigned int
{
	EST_Null = 0,
	EST_ProgBits = 1,
	EST_SymTab = 2,
	EST_StrTab = 3,
	EST_Rela = 4,
	EST_Hash = 5,
	EST_Dynamic = 6,
	EST_Note = 7,
	EST_NoBits = 8,
	EST_Rel = 9,
	EST_ShLib = 10,
	EST_DynSym = 11,
	EST_InitArray = 14,
	EST_FiniArray = 15,
	EST_PreInitArray = 16,
	EST_Group = 17,
	EST_SymTabShndx = 18,

	// SCE-specific section types
	EST_SCE_Rela = 0x60000000,
	EST_SCE_Nid = 0x61000001,
	EST_SCE_IopMod = 0x70000080,
	EST_SCE_EeMod = 0x70000090,
	EST_SCE_PspRela = 0x700000A0,
	EST_SCE_PpuRela = 0x700000A4
};

enum ElfProgramType : unsigned int
{
	EPT_Null = 0,
	EPT_Load = 1,
	EPT_Dynamic = 2,
	EPT_Interp = 3,
	EPT_Note = 4,
	EPT_ShLib = 5,
	EPT_Phdr = 6,
	EPT_Tls = 7,

	// SCE-specific segment types
	EPT_SceRela = 0x60000000,
	EPT_SceLicInfo1 = 0x60000001,
	EPT_SceLicInfo2 = 0x60000002,
	EPT_SceDynLibData = 0x61000000,
	EPT_SceProcessParam = 0x61000001,
	EPT_SceModuleParam = 0x61000002,
	EPT_SceRelRo = 0x61000010,  // for PS4
	EPT_SceComment = 0x6FFFFF00,
	EPT_SceLibVersion = 0x6FFFFF01,
	EPT_SceUnk70000001 = 0x70000001,
	EPT_SceIopMod = 0x70000080,
	EPT_SceEeMod = 0x70000090,
	EPT_ScePspRela = 0x700000A0,
	EPT_ScePspRela2 = 0x700000A1,
	EPT_ScePpuRela = 0x700000A4,
	EPT_SceSegSym = 0x700000A8
};

enum class ElfProgramFlags : unsigned int
{
	Execute = 0x1,
	Write = 0x2,
	Read = 0x4,

	// SCE-specific segment flags
	SpuExecute = 0x00100000,     // SPU Execute
	SpuWrite = 0x00200000,       // SPU Write
	SpuRead = 0x00400000,        // SPU Read
	RsxExecute = 0x01000000,     // RSX Execute
	RsxWrite = 0x02000000,       // RSX Write
	RsxRead = 0x04000000         // RSX Read
};

typedef struct _IMAGE_ELF64_HEADER {
	uint8_t e_ident[16]; // magic
	uint16_t e_type; //0x0010 ; ElfType
	uint16_t e_machine; //0x0012 ; ElfMachine
	uint32_t e_version; //0x0014
	uint64_t e_entry; //0x0018
	uint64_t e_phoff; //0x0020
	uint64_t e_shoff; //0x0028
	uint32_t e_flags; //0x0030
	uint16_t e_ehsize; //0x0034
	uint16_t e_phentsize; //0x0036
	uint16_t e_phnum; //0x0038
	uint16_t e_shentsize; //0x003A
	uint16_t e_shnum; //0x003C
	uint16_t e_shstrndx; //0x003E
} IMAGE_ELF64_HEADER, * PIMAGE_ELF64_HEADER; //Size: 0x0040

typedef struct  _ELF64_PROG_HEADER
{
public:
	uint32_t p_type; //0x0000
	uint32_t p_flags; //0x0004
	uint64_t p_offset; //0x0008
	uint64_t p_vaddr; //0x0010
	uint64_t p_paddr; //0x0018
	uint64_t p_filesz; //0x0020
	uint64_t p_memsz; //0x0028
	uint64_t p_align; //0x0030
} _ELF64_PROG_HEADER, * PELF64_PROG_HEADER; //Size: 0x0038

typedef struct _ELF64_SECTION_HEADER
{
public:
	uint32_t sh_name; //0x0000
	uint32_t sh_type; //0x0004
	uint64_t sh_flags; //0x0008
	uint64_t sh_addr; //0x0010
	uint64_t sh_offset; //0x0018
	uint64_t sh_size; //0x0020
	uint32_t sh_link; //0x0028
	uint32_t sh_info; //0x002C
	uint64_t sh_addralign; //0x0030
	uint64_t sh_entsize; //0x0038
} _ELF64_SECTION_HEADER, * PELF64_SECTION_HEADER; //Size: 0x0040
```
```cpp
inline bool PS3Memory::DumpELFHeaders(const char* name)
{
	const auto& vm = GetBaseVM(); // _IMAGE_ELF64_HEADER
	if (!vm)
		return false;

	/* parse program headers */
	const auto& core = vm - ELF_HEADER;
	const auto& ELF = Memory::ReadMemoryEx<_IMAGE_ELF64_HEADER>(vm);
	const auto& program_header_offset = _byteswap_uint64(ELF.e_phoff);
	const auto& program_header_size = _byteswap_ushort(ELF.e_phentsize);
	const auto& program_header_count = _byteswap_ushort(ELF.e_phnum);
	printf("[+][PS3Memory::DumpELF][%s] Dumping ELF Program Headers\n- VM: 0x%llX\n- ELF Header: 0x%llX\n- PH Offset: 0x%08X\n- PH Size: 0x%08X\n- PH Count: %d\n", name, core, vm, program_header_offset, program_header_size, program_header_count);

	//	std::vector<_ELF64_PROG_HEADER> program_headers;
	for (int i = 0; i < program_header_count; i++)
	{
		auto offset = vm + program_header_offset + (i * program_header_size);

		auto ph = Memory::ReadMemoryEx<_ELF64_PROG_HEADER>(offset);
		if (ph.p_filesz <= 0 || ph.p_memsz <= 0)
			continue;

		ph.p_type = _byteswap_ulong(ph.p_type);		
		ph.p_flags = _byteswap_ulong(ph.p_flags);	
		ph.p_offset = _byteswap_uint64(ph.p_offset);
		ph.p_vaddr = _byteswap_uint64(ph.p_vaddr);	
		ph.p_paddr = _byteswap_uint64(ph.p_paddr);	
		ph.p_filesz = _byteswap_uint64(ph.p_filesz);
		ph.p_memsz = _byteswap_uint64(ph.p_memsz);	
		ph.p_align = _byteswap_uint64(ph.p_align);	
		//	program_headers.push_back(ph);

		char buff[256];
		sprintf_s(buff, "%s_%d.ELF", name, i);

		const auto& va = core + ph.p_vaddr;
		printf("[-][PS3Memory::DumpELF] Dumping section to file @ 0x%llX with size 0x%08X\n", va, ph.p_filesz);
		Memory::DumpSectionToFile(buff, va, ph.p_filesz);
	}

	printf("[+][PS3Memory::DumpELF] finished.\n");

	return true;

	/* parse section headers */
	//	const auto& section_header_offset = _byteswap_uint64(ELF.e_shoff);
	//	const auto& section_header_size = _byteswap_ushort(ELF.e_shentsize);
	//	const auto& section_header_count = _byteswap_ushort(ELF.e_shnum);
	//	
	//	std::vector<_ELF64_SECTION_HEADER> section_headers;
	//	for (int i = 0; i < section_header_count; i++)
	//	{
	//		auto offset = vm + section_header_offset + (i * section_header_size);
	//	
	//		auto sh = Memory::ReadMemoryEx<_ELF64_SECTION_HEADER>(offset);
	//		// sh.sh_name; //0x0000
	//		sh.sh_type = _byteswap_ulong(sh.sh_type); //0x0004
	//		sh.sh_flags = _byteswap_uint64(sh.sh_flags); //0x0008
	//		sh.sh_addr = _byteswap_uint64(sh.sh_addr); //0x0010
	//		sh.sh_offset = _byteswap_uint64(sh.sh_offset); //0x0018
	//		sh.sh_size = _byteswap_uint64(sh.sh_size); //0x0020
	//		sh.sh_link = _byteswap_ulong(sh.sh_link); //0x0028
	//		sh.sh_info = _byteswap_ulong(sh.sh_info); //0x002C
	//		sh.sh_addralign = _byteswap_uint64(sh.sh_addralign); //0x0030
	//		sh.sh_entsize = _byteswap_uint64(sh.sh_entsize); //0x0038
	//	
	//		section_headers.push_back(sh);
	//	}
```

![](https://i.imgur.com/I2lUsk2.png)
## EXAMPLE DUMPER

```cpp
DWORD APIENTRY MainThread(LPVOID lparam)
{
	FILE* p;
	AllocConsole(); // create console window
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	HWND hwndConsole = GetConsoleWindow();
	freopen_s(&p, "CONOUT$", "w", stdout);
	ShowWindow(hwndConsole, SW_SHOW);

	if (Playstation3::InitCDK()) // performs "ResolveProcess" as shared above
	{
		const auto& vm = PS3Memory::GetBaseVM();
		const auto& sudo = PS3Memory::GetBaseSUDO();
		const auto& exec = PS3Memory::GetBaseEXEC();
		printf("[+][Demon's Souls]\n[+] VM: 0x%llX\n[+] SUDO: 0x%llX\n[+] EXEC: 0x%llX\n", vm, sudo, exec);

		Playstation3::PS3Memory::DumpELF("Demons Souls");
	}

	if (p)
		fclose(p);
	CloseHandle(hwndConsole);
	CloseHandle(hConsole);

	FreeLibraryAndExitThread(reinterpret_cast<HMODULE>(lparam), EXIT_SUCCESS);
	return EXIT_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID lparam)
{
	UNREFERENCED_PARAMETER(lparam);

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		HANDLE hThread = CreateThread(0, 0, MainThread, hInst, 0, 0);
		if (hThread)
			CloseHandle(hThread);
	}

	return TRUE;
}
```
```text
[+][Demon's Souls]
[+] VM: 0x300010000
[+] SUDO: 0x400010000
[+] EXEC: 0x500000000
[+][PS3Memory::DumpELF][Demon Souls] Dumping ELF Program Headers
- VM: 0x300000000
- ELF Header: 0x300010000
- PH Offset: 0x00000040
- PH Size: 0x00000038
- PH Count: 8
[-][PS3Memory::DumpELF] Dumping section to file @ 0x300010000 with size 0x01832D48
[-][PS3Memory::DumpELF] Dumping section to file @ 0x301850000 with size 0x0028609C
[-][PS3Memory::DumpELF] Dumping section to file @ 0x3019D8C68 with size 0x00000004
[-][PS3Memory::DumpELF] Dumping section to file @ 0x301842D00 with size 0x00000020
[-][PS3Memory::DumpELF] Dumping section to file @ 0x301842D20 with size 0x00000028
[+][PS3Memory::DumpELF] finished.
```

![](https://i.imgur.com/0khFoIn.png)
*Image shows the current health value residing at offset 0xC. The trace shows that the offset is rax+rbx+0xC at least when accessed , looking at the assembly around the instruction could indicate what rbx is though generally this is indicative of a sub-structure. *

## Tracing Class & Struct Members

I previously mentioned that using Cheat Engine was not really a good for reverse engineering the game internals. Lets take the following example and I'll try best to explain why it's not particularly good practice but can still be beneficial so long as you understand the nuances. Lets take "Demons Souls" and scan for the health value. Traditionally the easy method to get what function is accessing a variable is to "get what writes to this value" which will attach the debugger and trace whatever writes to it. Now with traditional PC games this will take you to some assembly code showing the instruction responsible for handling decrement or increment of the health value. With an emulator you will also be brought to some assembly but the key difference is that what cheat engine will be showing you is x64 assembly (8bytes) and in this case the instruction set would be PPC for the PS3. The instructions were 4bytes in length therefore making the architecture 4 byte aligned. These are two very different instruction sets and also if you were to set a breakpoint on the instruction responsible you would notice that the instruction responsible is executed for various other things ( patching it / nopping it will break various other components that use it as trampoline ) this 1 instruction also seems to be the only instruction responsible for decrementing health (you'll find that it changes over time and based on how health is applied it changes as well . . . besides the point ) it concludes that this is not the games assembly responsible and finding that is much more obtuse than I intend to get. 

So where does that leave us ? Well I mentioned that so long as you understand the nuances there is still some benefit to the approach described above. Take a look at the picture above. The instruction tells us at the very least that the health member is within a structure at 0xC and sure enough when we go in reclass an analyze this member we get our health, stamina, magic as well as many other variable. We can try to see what points to the address at health - 0xC to see if its possible to get a global / static pointer to this section of memory. 

![](https://i.imgur.com/6zVG9lV.png)
*yellow: indicates the current address. red: indicates pointers to other sections of memory.*

![](https://i.imgur.com/y2jWd0C.png)
*additional pointers , one referencing somewhere below player stats.*

![](https://i.imgur.com/wWXPMPi.png)
![](https://i.imgur.com/tYXe7Yt.png)
*0x301E7668 - pointer to character stats with many other pointers around it indicating this is a global struct of sorts*

![](https://i.imgur.com/eikK62L.png)
![](https://i.imgur.com/dkSihKu.png)
*0x1B4EF9C - base pointer that points to some global array of pointers ( one of which being a pointer to character stats ). This is most certainly a data pointer that is used as a static pointer in the game code somewhere. The chain wont change but the addresses might that is why we search for pointers.*

![](https://i.imgur.com/SifHYxj.png)
*demonstrates the difference between native windows pointers and how the last 2 images showed PS3 pointers ( mainly the tooling though as ReClass doesn't have a RPCS3 plugin , since we know what a pointer looks like now we could do the same thing )*

## Pointers & Object Structures

Identifying pointers as well as navigating them can be quite tricky. Some people like myself rely on tools such as ReClass to analyze memory with a live process and is a powerful tool when trying to find pointers and other variables in a process. With your typical windows process it's not uncommon to have reclass automatically resolve a pointer and either display a string or hovering will show the section of memory for quick analysis before applying the pointer type to further analyze. With RPCS3 emulated game memory it will not be immediately obvious like in the 3rd screenshot shown above ( shows the string L"GameList" via pointer and the above pointer points 0x10 bytes before the string which contains the size and max size ). The first 2 images show emulated game memory from the VM "g_base_address" section in RPCS3 process memory ( as previously demonstrated emulators vm base is "0x300000000".  ) and also show the section of memory that contains the player health, stamina and magic values. Recall that the address for health is "3301E802C" and that the instruction was "[rax+rbx+0C],r14d" where health is rbx+0xC. Subtracting 0xC from 0x3301E802C results in an address of "3301E8020". Performing a scan of the value "301E8020" stripped of the vm base address ( as weve seen that pointers will never contain it ) , we get a few results but we only care about the ones in the vm range ( ignore sudo as well ). From there its just trying to walk back and get the closest you can to the base address ( so in this case not leading with 0x30000000 as that is basically in the heap range and not allocated when the game is first started ). I'm providing a C++ function below for performing pointer scans ( basically any scan really ) in RPCS3 memory range using methods shared up until this point in the guide.
```cpp
inline bool PS3Memory::PointerScan(const u64_t& addr, OUT std::vector<u64_t>& result, const size_t& depth)
{
	/*
	 depth: how far back to go from the base address. Take the input 0x3301E8010. Let's say the entire region comes up with nothing pointing to it and there is a value passed for depth the method would walk backwards 4 bytes at a time searching for a pointer. 
	 addr: 0x3301E8020
	 core: 0x300000000
	 mask: addr & 0xFFFFFF -> 0x1E8020
	 mask2: addr & 0xFFFFFFFF -> 0x301E8020
	 nibble: (addr >> 32) & 0xF -> 0x3

	 the goal is to scan the entire VM region for the value matching 0x301E8020. 
	  - It would be nice if the entire section could be read at once (0x300000000 - 0x3FFFFFFFF) and iterate 4 bytes at a time. swapping bytes and comparing with the input search value. 
	*/

	const auto& vm = GetBaseVM(false);
	if (!vm)
		return false;

	u8_t* scan_bytes = reinterpret_cast<u8_t*>(vm); // im in danger

	SIZE_T read_sz{ 0 }; // read size 
	constexpr size_t sz = 4;
	constexpr size_t section_sz = 0x100000000; // size of section to scan
	u64_t input_base = addr & 0xFFFFFFFF; // (addr >> 32) & 0xF > 0 ? addr & 0xFFFFFFFF : addr & 0xFFFFFF; // mask leading bytes
	printf("[+][PS3Memory::PointerScan] vm: 0x%llX : input: 0x%llX : masked: 0x%llX : bytes: ", vm, addr, input_base);

	u8_t input_bytes[sz];
	for (int i = 0; i < 4; i++)
	{
		input_bytes[i] = (input_base >> (24 - (i * 8))) & 0xFF; // 30 1E 80 20
		printf("%02X ", input_bytes[i]);
	}
	printf("\n");

	size_t scan_act = 0;
	std::vector<u64_t> scan_results;
	for (int L = 0; L < depth + 1; L++)
	{
		if (L != 0)
		{
			input_base -= 0x4;
			printf("[+][PS3Memory::PointerScan] adjusting bytes for depth: ");
			for (int K = 0; K < 4; K++)
			{
				input_bytes[K] = (input_base >> (24 - (K * 8))) & 0xFF; // 30 1E 80 1C ; example -4  
				printf("%02X ", input_bytes[K]);
			}
			printf("\n");
		}

		while (scan_act < section_sz)
		{
			/* safely walk sections */
			MEMORY_BASIC_INFORMATION mbi{  };
			if (!VirtualQuery(scan_bytes + scan_act, &mbi, sizeof(mbi)))
			{
				printf("[!][PS3Memory::PointerScan] virtual query failed with error code: 0x%08X\n", GetLastError());
				break;
			}

			/* get region size & determine if memory is commited */
			size_t region_sz = mbi.RegionSize;
			if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
			{
				printf("[-][PS3Memory::PointerScan] skipping section @ 0x%llx with size 0x%08X\n", scan_bytes + scan_act, region_sz);
				scan_act += region_sz;
				continue;
			}

			/* walk region */
			for (size_t i = 0; i + sz <= region_sz; i++)
			{
				bool found = true;

				/* walk bytes */
				for (int j = 0; j < sz; j++)
				{
					// 30 1E 80 10
					if (scan_bytes[scan_act + i + j] != input_bytes[j])
					{
						found = false;
						break;
					}
				}

				/* was something found ? */
				if (found)
				{
					auto address = vm + scan_act + i;
					scan_results.push_back(address);
					printf("[+][PS3Memory::PointerScan] 0x%llX -> 0x%llX\n", address, input_base);
				}
			}
			scan_act += region_sz;
		}
		
		scan_act = 0; // reset scan for next level (depth)
	}

	result = scan_results;

	printf("[+][PS3Memory::PointerScan][0x%llX] obtained %d results.\n", scan_results.size() > 0 ? scan_results[0] : 0, scan_results.size());

	return scan_results.size() > 0;
}
```

## Demon's Souls Data Structures

```cpp
namespace Offsets
{
	static constexpr auto g_WorldCharMan = 0x1B4EF9C;
}

namespace Structs
{
	class FProperty
	{
	public:
		u32_t value; //0x0000
		u32_t maxValue; //0x0004
	}; //Size: 0x0008
}

namespace Classes
{
	class WorldCharacterManager
	{
	public:
		char pad_0000[8]; //0x0000	
		u32_t pCharData; //0x0008 : CSCharData
		char pad_000C[120]; //0x000C
		u32_t pChar; //0x0084	: CSChar
		char pad_0088[56]; //0x0088
	}; //Size: 0x00C0

	class CSCharData
	{
	public:
		char pad_0000[20]; //0x0000
		u32_t MaxHealth; //0x0014
		char pad_0018[8]; //0x0018
		u32_t MaxMP; //0x0020
		char pad_0024[12]; //0x0024
		u32_t MaxStamina; //0x0030
		char pad_0034[4]; //0x0034
		Structs::FProperty Vitality; //0x0038
		Structs::FProperty Intelligence; //0x0040
		Structs::FProperty Endurance; //0x0048
		Structs::FProperty Srength; //0x0050
		Structs::FProperty Dexterity; //0x0058
		Structs::FProperty Magic; //0x0060
		Structs::FProperty Faith; //0x0068
		Structs::FProperty Luck; //0x0070
		u32_t Souls; //0x0078
		char pad_008C[21]; //0x007C
		wchar_t Name[16]; //0x0091
	}; //Size: 0x00B1

	class CSChar
	{
	public:
		char pad_0000[4]; //0x0000
		u32_t pInventory; //0x0004
		char pad_0008[8]; //0x0008
		CSCharData CharData; //0x0010
	}; //Size: 0x00C1

	class CSCharInventory
	{
	public:
		u32_t pChar; //0x0000
		u32_t pCharEquipment; //0x0004 : CSCharInventory*
		char pad_0008[12]; //0x0008
		u32_t szItemArray; //0x0014
		//	class ItemData ItemArray[2048]; //0x0018	: CSInventoryItemData[szItemArray]
		//	char pad_10018[356]; //0x10018
	}; //Size: 0x0018

	class CSInventoryItemData
	{
	public:
		u32_t ItemType; //0x0000
		u32_t ItemID; //0x0004
		u32_t Quantity; //0x0008
		u32_t InventorySlot; //0x000C
		char pad_0010[16]; //0x0010
	}; //Size: 0x0020
}

namespace tools
{
	inline u64_t GetWorldCharacterManager(OUT u64_t& res)
	{
		res = 0;
		
		const auto vm = PS3Memory::GetBaseVM(false);
		if (!vm)
			return res;
		
		const auto p = vm + Offsets::g_WorldCharMan;
		if (!p)
			return res;

		res = PS3Memory::ReadLong(p) + vm;
		if (res == vm)
			res = 0;

		return res;
	}

	inline u64_t GetLocalCharacterData(OUT u64_t& res)
	{
		res = 0;

		const auto vm = PS3Memory::GetBaseVM(false);
		if (!vm)
			return res;

		if (!GetWorldCharacterManager(res))
			return res;

		const auto& wcm = Memory::ReadMemoryEx<Classes::WorldCharacterManager>(res);
		
		res = _byteswap_ulong(wcm.pCharData) + vm;
		if (res == vm)
			res = 0;

		return res;
	}

	inline u64_t GetLocalCharacterInventory(OUT u64_t& res)
	{
		res = 0;

		const auto vm = PS3Memory::GetBaseVM(false);
		if (!vm)
			return res;

		if (!GetWorldCharacterManager(res))
			return res;

		const auto& wcm = Memory::ReadMemoryEx<Classes::WorldCharacterManager>(res);

		res = _byteswap_ulong(wcm.pChar) + vm;
		if (res == vm)
		{
			res = 0;
			return false;
		}

		const auto& cdata = Memory::ReadMemoryEx<Classes::CSChar>(res);

		res = _byteswap_ulong(cdata.pInventory) + vm;
		if (res == vm)
			res = 0;

		return res;
	}

	inline std::string GetItemNameByID(const u32_t& id)
	{
		const auto it = Data::ItemNames.find(id);
		if (it != Data::ItemNames.end())
			return it->second;
		return "Unknown Item";
	}

	inline void DumpPlayerInventory()
	{
		const auto& vm = PS3Memory::GetBaseVM(false);
		if (!vm)
			return;

		u64_t pInventory;
		if (!GetLocalCharacterInventory(pInventory))
			return;

		const auto& inventory = Memory::ReadMemoryEx<Classes::CSCharInventory>(pInventory);
		if (!inventory.szItemArray)
			return;

		const size_t szArray = _byteswap_ulong(inventory.szItemArray);

		const auto pItemArray = pInventory + (offsetof(Classes::CSCharInventory, Classes::CSCharInventory::szItemArray) + 0x4);
		Classes::CSInventoryItemData* p_items = reinterpret_cast<Classes::CSInventoryItemData*>(pItemArray);
		for (int i = 0; i < szArray; i++)
		{
			Classes::CSInventoryItemData item = p_items[i];
			const auto& itemType = _byteswap_ulong(item.ItemType);
			if (itemType == 0xFFFFFFFF)
				break;

			const auto& itemID = _byteswap_ulong(item.ItemID);
			const auto& itemCount = _byteswap_ulong(item.Quantity);
			const auto& itemSlot = _byteswap_ulong(item.InventorySlot);
			const auto& itemName = GetItemNameByID(itemID);
			printf("[%d][0x%llX][%s]\n- ID: 0x%08X\n- COUNT: %d\n- SLOT: %d\n", i, pItemArray + (i * sizeof(Classes::CSInventoryItemData)), itemName.c_str(), itemID, itemCount, itemSlot);
		}
	}
}
```

## Pointer Scanning the RPCS3 VM

After mapping the basic pointer layout, I set out to make a function which scans the VM section for addresses that point to whatever address you feed it. I did manage to get something working take a look at the following output. it found 2 addresses in demon souls around the souls area which includes other player stats , refer to the bottom of my post for the complete memory layout

![](https://i.imgur.com/ZDERihT.png)
![](https://i.imgur.com/ThOaKag.png)
![](https://i.imgur.com/mCJOr5x.png)

```text
[+][PS3Memory::PointerScan] vm: 0x300000000 : input: 0x3301E8098 : masked: 0x301E8098 : bytes: 30 1E 80 98
// skipping a bunch of lines as it found nothing up until this point
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 20
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[+][PS3Memory::PointerScan] 0x3301E7668 -> 0x301E8020
[+][PS3Memory::PointerScan] 0x3301E82F0 -> 0x301E8020
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
```

```text
[+][PS3Memory::PointerScan] vm: 0x300000000 : input: 0x3301E7668 : masked: 0x301E7668 : bytes: 30 1E 76 68
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 76 64
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 76 60
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[+][PS3Memory::PointerScan] 0x301B4EF9C -> 0x301E7660
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan][0x301B4EF9C] obtained 1 results
```

<details>
<summary>full dump</summary>

```text
[+] RPCS3 CDK Initialized.
[+] RPCS3 VM: 0x300010000
[+] RPCS3 SUDO: 0x400010000
[+] RPCS3 EXEC: 0x500000000
[-] Dumping section to file @ 0x300010000 with size 0x01832D48
[-] Dumping section to file @ 0x301850000 with size 0x004DB5D8
[-] Dumping section to file @ 0x300000000 with size 0x00000000
[-] Dumping section to file @ 0x300000000 with size 0x00000000
[-] Dumping section to file @ 0x300000000 with size 0x00000000
[-] Dumping section to file @ 0x3019D8C68 with size 0x00000434
[-] Dumping section to file @ 0x301842D00 with size 0x00000020
[-] Dumping section to file @ 0x301842D20 with size 0x00000028
[+][PS3Memory::PointerScan] vm: 0x300000000 : input: 0x3301E8098 : masked: 0x301E8098 : bytes: 30 1E 80 98
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 94
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 90
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 8C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 88
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 84
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 80
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 7C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 78
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 74
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 70
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 6C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 68
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 64
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 60
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 5C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 58
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 54
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 50
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 4C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 48
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 44
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 40
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 3C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 38
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 34
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 30
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 2C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 28
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 24
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 20
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[+][PS3Memory::PointerScan] 0x3301E7668 -> 0x301E8020
[+][PS3Memory::PointerScan] 0x3301E82F0 -> 0x301E8020
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 1C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 18
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 14
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 10
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[+][PS3Memory::PointerScan] 0x3301E76E4 -> 0x301E8010
[+][PS3Memory::PointerScan] 0x3301E8540 -> 0x301E8010
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 0C
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 08
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 04
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 80 00
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[+][PS3Memory::PointerScan] 0x332301DA9 -> 0x301E8000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 7F FC
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan] adjusting bytes for depth: 30 1E 7F F8
[-][PS3Memory::PointerScan] skipping section @ 0x300000000 with size 0x00010000
[-][PS3Memory::PointerScan] skipping section @ 0x302110000 with size 0x0DEF0000
[-][PS3Memory::PointerScan] skipping section @ 0x3111b0000 with size 0x1EE50000
[-][PS3Memory::PointerScan] skipping section @ 0x339400000 with size 0x06C00000
[-][PS3Memory::PointerScan] skipping section @ 0x340400000 with size 0x7FC00000
[-][PS3Memory::PointerScan] skipping section @ 0x3c0010000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c03d0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3c07a0000 with size 0x00384000
[-][PS3Memory::PointerScan] skipping section @ 0x3cf900000 with size 0x00700000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0000000 with size 0x00001000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0101000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0113000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d011d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0127000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d012d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d013f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0145000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0157000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0169000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d017b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d018d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d019f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01b5000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d01f7000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0209000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d021b000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d022d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0237000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d023d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0247000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0259000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d025f000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0263000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d026d000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0270000 with size 0x00011000
[-][PS3Memory::PointerScan] skipping section @ 0x3d0291000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02a3000 with size 0x00002000
[-][PS3Memory::PointerScan] skipping section @ 0x3d02b5000 with size 0x0FD4B000
[-][PS3Memory::PointerScan] skipping section @ 0x3e0000000 with size 0x08000000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8000000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8040000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8080000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e80c0000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8100000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8140000 with size 0x00040000
[-][PS3Memory::PointerScan] skipping section @ 0x3e8180000 with size 0x17E90000
[+][PS3Memory::PointerScan][0x3301E7668] obtained 5 results.
```

</details>

```cpp
inline bool PS3Memory::PointerScan(const unsigned __int64& addr, OUT std::vector<unsigned long long>& result, const size_t& depth)
{

	/*
	 depth: how far back to go from the base address. Take the input 0x3301E8010. Let's say the entire region comes up with nothing pointing to it and there is a value passed for depth the method would walk backwards 4 bytes at a time searching for a pointer. 
	 addr: 0x3301E8010
	 core: 0x300000000
	 mask: addr & 0xFFFFFF -> 0x1E8010
	 mask2: addr & 0xFFFFFFFF -> 0x301E8010
	 nibble: (addr >> 32) & 0xF -> 0x3

	 the goal is to scan the entire VM region for the value matching 0x301E8010. 
	  - It would be nice if the entire section could be read at once (0x300000000 - 0x3FFFFFFFF) and iterate 4 bytes at a time. swapping bytes and comparing with the input search value. 
	*/

	const auto& vm = GetBaseVM(false);
	if (!vm)
		return false;

	unsigned __int8* scan_bytes = reinterpret_cast<unsigned __int8*>(vm); // hehe "im in danger"

	SIZE_T read_sz{ 0 }; // read size 
	constexpr size_t sz = 4;
	constexpr size_t section_sz = 0x100000000; // size of section to scan
	unsigned long long input_base = addr & 0xFFFFFFFF; // (addr >> 32) & 0xF > 0 ? addr & 0xFFFFFFFF : addr & 0xFFFFFF; // mask leading bytes
	printf("[+][PS3Memory::PointerScan] vm: 0x%llX : input: 0x%llX : masked: 0x%llX : bytes: ", vm, addr, input_base);

	unsigned __int8 input_bytes[sz];
	for (int i = 0; i < 4; i++)
	{
		input_bytes[i] = (input_base >> (24 - (i * 8))) & 0xFF; // 30 1E 80 10
		printf("%02X ", input_bytes[i]);
	}
	printf("\n");

	size_t scan_act = 0;
	std::vector<unsigned long long> scan_results;
	for (int L = 0; L < depth + 1; L++)
	{
		if (L != 0)
		{
			input_base = input_base - 0x4;
			printf("[+][PS3Memory::PointerScan] adjusting bytes for depth: ");
			for (int K = 0; K < 4; K++)
			{
				input_bytes[K] = (input_base >> (24 - (K * 8))) & 0xFF; // 30 1E 80 0C ; example -4  
				printf("%02X ", input_bytes[K]);
			}
			printf("\n");
		}

		while (scan_act < section_sz)
		{
			/* safely walk sections */
			MEMORY_BASIC_INFORMATION mbi{  };
			if (!VirtualQuery(scan_bytes + scan_act, &mbi, sizeof(mbi)))
			{
				printf("[!][PS3Memory::PointerScan] virtual query failed with error code: 0x%08X\n", GetLastError());
				break;
			}

			/* get region size & determine if memory is commited */
			size_t region_sz = mbi.RegionSize;
			if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
			{
				printf("[-][PS3Memory::PointerScan] skipping section @ 0x%llx with size 0x%08X\n", scan_bytes + scan_act, region_sz);
				scan_act += region_sz;
				continue;
			}

			/* walk region */
			for (size_t i = 0; i + sz <= region_sz; i++)
			{
				bool found = true;

				/* walk bytes */
				for (int j = 0; j < sz; j++)
				{
					// 30 1E 80 10
					if (scan_bytes[scan_act + i + j] != input_bytes[j])
					{
						found = false;
						break;
					}
				}

				/* was something found ? */
				if (found)
				{
					auto address = vm + scan_act + i;
					scan_results.push_back(address);
					printf("[+][PS3Memory::PointerScan] 0x%llX -> 0x%llX\n", address, input_base);
				}
			}
			scan_act += region_sz;
		}
		scan_act = 0; // reset scan for next
	}

	result = scan_results;

	printf("[+][PS3Memory::PointerScan][0x%llX] obtained %d results.\n", scan_results.size() > 0 ? scan_results[0] : 0, scan_results.size());

	return scan_results.size() > 0;
}
```

### Demon's Souls Player Stats

```cpp
// g_char = 0x01B4EF9C
// when reading a pointer add vm to it so if the vm base is 0x300000000 the address would be 0x301B4EF9C
// the result of 0x301B4EF9C could be 0x301E7660 so add vm to that and get 0x3301E7660
class g_Char
{
public:
	uint32_t pCharacterInfo; //0x0000
	char pad_0004[124]; //0x0004
}; //Size: 0x0080
static_assert(sizeof(g_Char) == 0x80);

class PlayerCharacter
{
public:
	char pad_0000[8]; //0x0000
	uint32_t pStats; //0x0008
	char pad_000C[116]; //0x000C
}; //Size: 0x0080
static_assert(sizeof(PlayerCharacter) == 0x80);

class FProperty
{
public:
	uint32_t value; //0x0000
	uint32_t maxValue; //0x0004
}; //Size: 0x0008
static_assert(sizeof(FProperty) == 0x8);

class PlayerStats
{
public:
	char pad_0000[20]; //0x0000
	uint32_t MaxHealth; //0x0014
	char pad_0018[8]; //0x0018
	uint32_t MaxMP; //0x0020
	char pad_0024[12]; //0x0024
	uint32_t MaxStamina; //0x0030
	char pad_0034[4]; //0x0034
	class FProperty Vitality; //0x0038
	class FProperty Intelligence; //0x0040
	class FProperty Endurance; //0x0048
	class FProperty Srength; //0x0050
	class FProperty Dexterity; //0x0058
	class FProperty Magic; //0x0060
	class FProperty Faith; //0x0068
	class FProperty Luck; //0x0070
	uint32_t Souls; //0x0078
}; //Size: 0x007c
static_assert(sizeof(PlayerStats) == 0x7c);
```

## Credits and References

- [ELF64 — Linux Inside](https://0xax.gitbooks.io/linux-insides/content/Theory/linux-theory-2.html)
- [Linux ELF definitions](https://github.com/torvalds/linux/blob/16f73eb02d7e1765ccab3d2018e0bd98eb93d973/include/uapi/linux/elf.h#L220)
- [RPCS3 source code](https://github.com/RPCS3/rpcs3)
- dfanz0r for sharing some of their wisdom
