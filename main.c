#include "stdafx.h"


/*
	20/06/2021 update
	- auto updates beta (scetchy way, can work for some CSGO updates)
	- this doesn't always work at first try, if its not working, pleace do sleep again
*/

/*
	11/09/2023 update
	- code cleanup
*/


//
// static global variables
//
EFI_GUID gEfiSmmBase2ProtocolGuid = { 0xf4ccbfb7, 0xf6e0, 0x47fd, { 0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91 }};
EFI_GUID gEfiSmmSwDispatch2ProtocolGuid = { 0x18a3c6dc, 0x5eea, 0x48c8, {0xa1, 0xc1, 0xb5, 0x33, 0x89, 0xf9, 0x89, 0x99 }};
EFI_GUID gEfiSmmCpuProtocolGuid = { 0xeb346b97, 0x975f, 0x4a9f, { 0x8b, 0x22, 0xf8, 0xe9, 0x2b, 0xb3, 0xd5, 0x69 }};


EFI_RUNTIME_SERVICES  *gRT;
EFI_BOOT_SERVICES     *gBS;
EFI_SYSTEM_TABLE      *gST;
EFI_SMM_SYSTEM_TABLE2 *gSMST;

#define SW_SMI_VAL 0x56

inline int to_lower_imp(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c + 'a' - 'A';
	else
		return c;
}

inline int strcmpi_imp(const char* s1, const char* s2)
{
	while (*s1 && (to_lower_imp(*s1) == to_lower_imp(*s2)))
	{
		s1++;
		s2++;
	}
	return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

inline int wcscmpi_imp(const unsigned short* s1, const unsigned short* s2)
{
	while (*s1 && (to_lower_imp(*s1) == to_lower_imp(*s2)))
	{
		s1++;
		s2++;
	}
	return *(const unsigned short*)s1 - *(const unsigned short*)s2;
}

unsigned __int64 dword_244()
{
        unsigned __int64 result; // rax

        result = __readmsr(0xC0010015) | 1;
        __writemsr(0xC0010015, result);
        return result;
}

__int64 __fastcall qword_388(__int64 a1, __int64 a2, __int64 a3)
{
        if ( a3 )
        {
                if (*(unsigned char *)(a3 + 8) == SW_SMI_VAL)
                {
                        /*
                        unsigned __int64 v3 = __readmsr(0xC0010015);
                        if ( !(v3 & 1) )
                        {
                                __writemsr(0xC0010015, v3 | 1);

                                //  gSMST->NumberOfCpus
                                for (QWORD i = 1; i < *(QWORD *)(gSMST + 0x80); ++i )
                                        // SmmStartupThisAp(PVOID Procedure, UINT64 CpuNumber, VOID **ProcArguments)
                                        // gSMST->SmmStartupThisAp(&dword_244, i, 0i64);
                                        (*(void (__fastcall **)(QWORD, unsigned __int64, QWORD))(gSMST + 0x70))((QWORD)dword_244, i, 0i64);

                        }
                        */
                        return 0;
                }
        }
        return 0;
}

BOOLEAN pm_read(QWORD address, VOID *buffer, QWORD length)
{
        if (address < 1)
                return 0;
        
	for (QWORD i = 0; i < length; i++)
		*(unsigned char*)(((QWORD)buffer + i)) = *(unsigned char*)(((QWORD)address + i));

        return 1;
}

unsigned short pm_read_i16(QWORD address)
{
	unsigned short buffer = 0;
	pm_read(address, &buffer, sizeof(buffer));
	return buffer;
}

DWORD pm_read_i32(QWORD address)
{
	DWORD buffer = 0;
	pm_read(address, &buffer, sizeof(buffer));
	return buffer;
}

QWORD pm_read_i64(QWORD address)
{
	QWORD buffer = 0;
	pm_read(address, &buffer, sizeof(buffer));
	return buffer;
}

BOOLEAN pm_write(QWORD address, VOID *buffer, QWORD length)
{
        if (address < 1)
                return 0;
        
	for (QWORD i = 0; i < length; i++)
		*(unsigned char*)(((QWORD)address + i)) = *(unsigned char*)(((QWORD)buffer + i));

        return 1;
}

static QWORD pm_translate(QWORD dir, QWORD va)
{
	__int64 v2; // rax
	__int64 v3; // rax
	__int64 v5; // rax
	__int64 v6; // rax

	v2 = pm_read_i64(8 * ((va >> 39) & 0x1FF) + dir);
	if ( !v2 )
		return 0i64;

	if ( (v2 & 1) == 0 )
		return 0i64;

	v3 = pm_read_i64((v2 & 0xFFFFFFFFF000i64) + 8 * ((va >> 30) & 0x1FF));
	if ( !v3 || (v3 & 1) == 0 )
		return 0i64;

	if ( (v3 & 0x80u) != 0i64 )
		return (va & 0x3FFFFFFF) + (v3 & 0xFFFFFFFFF000i64);

	v5 = pm_read_i64((v3 & 0xFFFFFFFFF000i64) + 8 * ((va >> 21) & 0x1FF));
	if ( !v5 || (v5 & 1) == 0 )
		return 0i64;

	if ( (v5 & 0x80u) != 0i64 )
		return (va & 0x1FFFFF) + (v5 & 0xFFFFFFFFF000i64);

	v6 = pm_read_i64((v5 & 0xFFFFFFFFF000i64) + 8 * ((va >> 12) & 0x1FF));
	if ( v6 && (v6 & 1) != 0 )
		return (va & 0xFFF) + (v6 & 0xFFFFFFFFF000i64);

	return 0i64;
}

QWORD vm_get_export_ex(QWORD cr3, BOOLEAN wow64, QWORD module, const char *export_name)
{
	QWORD a0;
	DWORD a1[4], a2[30];

	a0 = module + pm_read_i16(pm_translate(cr3, module + 0x3C));
	a0 = module + pm_read_i32(pm_translate(cr3, a0 + 0x88 - wow64 * 16));
	a1[0]=0;
	pm_read(pm_translate(cr3, a0 + 0x18), &a1[0], 8);
	pm_read(pm_translate(cr3, a0 + 0x20), &a1[2], 8);
	while (a1[0]--) {	
		a0 = pm_read_i32(pm_translate(cr3, module + a1[2] + (a1[0] * 4)));
		pm_read(pm_translate(cr3, module + a0), &a2, sizeof(a2));
		if (!strcmpi_imp((CHAR8*)a2, export_name))
			return (module + pm_read_i32(pm_translate(cr3, module + a1[1] +
				(pm_read_i16(pm_translate(cr3,module + a1[3] + (a1[0] * 2))) * 4))));
	}
	return 0;
}

QWORD PsInitialSystemProcess;
static DWORD offset_PsGetProcessImageFileName;
static DWORD offset_PsGetProcessExitProcessCalled;
static DWORD offset_ActiveProcessLinks;
static DWORD offset_PsGetProcessWow64Process;
static DWORD offset_PsGetProcessPeb;
static QWORD system_cr3;


static QWORD get_process_by_name(const char *process_name)
{
	QWORD entry;
	char name[15]={0};

        QWORD proc = *(QWORD*)(pm_translate(system_cr3, PsInitialSystemProcess));
	entry = proc;
	do {
		pm_read(pm_translate(system_cr3, entry + offset_PsGetProcessImageFileName), name, 15);
		name[14]=0;
		
		DWORD exitcalled = *(DWORD*)(pm_translate(system_cr3, entry + offset_PsGetProcessExitProcessCalled));
		exitcalled = exitcalled >> 2;
		exitcalled = exitcalled & 1;

		if (!exitcalled && !strcmpi_imp(name, process_name))
			return entry;

		entry = *(QWORD*)(pm_translate(system_cr3, entry + offset_ActiveProcessLinks));

		if (entry == 0)
			break;

		entry = entry - offset_ActiveProcessLinks;


	} while (entry != proc) ;
	return 0;
}

QWORD   ntoskrnl;
BOOLEAN gInOs;

QWORD   g_process;
QWORD   g_cvar;
QWORD   g_process_cr3;
QWORD   g_process_peb;
BOOLEAN g_process_wow64;


#define min(a, b)  (((a) < (b)) ? (a) : (b))
BOOLEAN vm_read(QWORD address, VOID *buffer, QWORD length)
{
	/*
	return pm_read(pm_translate(g_process_cr3, address), buffer, length);
	*/

	QWORD total_size = length;
	QWORD offset = 0;
	QWORD bytes_read=0;

	while (total_size) {
		QWORD physical_address = pm_translate(g_process_cr3, address + offset);
		if (!physical_address) {
			if (total_size >= 0x1000)
			{
				bytes_read = 0x1000;
			}
			else
			{
				bytes_read = total_size;
			}

			for (QWORD i = bytes_read; i--;)
			{
				*(unsigned char*)((QWORD)buffer + offset + i) = 0;
			}

			goto E0;
		}
		QWORD current_size = min(0x1000 - (physical_address & 0xFFF), total_size);

		if (!pm_read( physical_address, (void*)((QWORD)buffer + offset), current_size))
		{
			break;
		}
		bytes_read = current_size;
	E0:
		total_size -= bytes_read;
		offset += bytes_read;
	}
	return 1;
}

BOOLEAN vm_write(QWORD address, VOID *buffer, QWORD length)
{
	return pm_write(pm_translate(g_process_cr3, address), buffer, length);
}

BOOLEAN vm_write_i32(QWORD address, DWORD value)
{
	return vm_write(address, &value, sizeof(value));
}

QWORD vm_read_i64(QWORD address, QWORD length)
{
	QWORD buffer = 0;
	vm_read(address, &buffer, length);
	return buffer;
}


DWORD vm_read_i32(QWORD address)
{
	DWORD buffer = 0;
	vm_read(address, &buffer, 4);
	return buffer;
}


inline unsigned long long wcslen_imp(const unsigned short *str)
{
	const unsigned short *s;

	for (s = str; *s; ++s)
		;

	return (s - str);
}

QWORD vm_get_module(const unsigned short *module_name)
{
	QWORD peb;
	DWORD a0[5];
	QWORD a1, a2, a3[15];

	if (g_process_wow64) {
		peb = g_process_peb;
		a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10;
	} else {
		peb = g_process_peb;
		a0[0] = 0x08, a0[1] = 0x18, a0[2] = 0x20, a0[3] = 0x50, a0[4] = 0x20;
	}

	if (peb == 0)
		return 0;

	a1 = vm_read_i64(vm_read_i64(peb + a0[1], a0[0]) + a0[2], a0[0]);

        if (a1 == 0)
                return 0;

	a2 = a2 = vm_read_i64(a1 + a0[0], a0[0]);
        if (a2 == 0)
                return 0;


	QWORD name_length = (wcslen_imp(module_name) * 2) + 2;

	while (a1 != a2)
	{
		vm_read(vm_read_i64(a1 + a0[3], a0[0]), a3, name_length);
		if (!wcscmpi_imp((CHAR16*)a3, module_name))
		{
			return vm_read_i64(a1 + a0[4], a0[0]);
		}
		a1 = vm_read_i64(a1, a0[0]);
	}
	return 0;
}

QWORD vm_get_export(QWORD module, const char *export_name)
{
	return vm_get_export_ex(g_process_cr3, g_process_wow64, module, export_name);
}

inline unsigned long long strlen_imp(const char *str)
{
	const char *s;

	for (s = str; *s; ++s)
		;

	return (s - str);
}

QWORD get_interface(QWORD base, const char *name)
{
	QWORD export_address = vm_get_export(base, "CreateInterface");
	if (export_address == 0)
	{
		return 0;
	}

	
	QWORD interface_entry = vm_read_i64((export_address + 7) + vm_read_i32(export_address + 3), 8);
	if (interface_entry == 0)
	{
		return 0;
	}

	QWORD name_length = strlen_imp(name);

	while (1)
	{
		char interface_name[120];
		vm_read(
			vm_read_i64(interface_entry + 8, 8),
			interface_name,
			name_length
			);
		
		if (!strcmpi_imp(interface_name, name))
		{
			//
			// lea    rax, [rip+0xXXXXXX]
			// ret
			//
			QWORD vfunc = vm_read_i64(interface_entry, 8);


			//
			// emulate vfunc call
			//
			QWORD addr = (vfunc + 7) + vm_read_i32(vfunc + 3);

			return addr;
		}

		interface_entry = vm_read_i64(interface_entry + 16, 8);
		if (interface_entry == 0)
			break;
	}
	return 0;
}

static QWORD get_convar(const char *name)
{
	QWORD tier0 = vm_get_module(L"tier0.dll");
	if (tier0 == 0)
	{
		return 0;
	}

	QWORD engine_cvar = get_interface(tier0, "VEngineCvar0");
	if (engine_cvar == 0)
	{
		return 0;
	}

	QWORD objs = vm_read_i64(engine_cvar + 64, 8);

	QWORD name_length = strlen_imp(name);

	for (DWORD i = 0; i < vm_read_i32(engine_cvar + 160); i++)
	{
		QWORD entry = vm_read_i64(objs + 16 * i, 8);
		if (entry == 0)
		{
			break;
		}
		
		char convar_name[120];
		vm_read(vm_read_i64(entry + 0x00, 8), convar_name, name_length);

		if (!strcmpi_imp(convar_name, name))
		{
			return entry;
		}
	}
	return 0;
	/*
	WORD  convar_id = vm::read_i16(game_handle, engine_cvar + 80);
	while (1)
	{
		QWORD entry = vm::read_i64(game_handle, objs + 16 * convar_id);
		
		char convar_name[120]{};
		vm::read(game_handle, vm::read_i64(game_handle, entry + 0x00), convar_name, 120);

		if (!strcmpi_imp(convar_name, name))
		{
		}

		convar_id = vm::read_i16(game_handle, objs + 16 * convar_id + 10);
		if (convar_id == 0xFFFF)
			break;
	}
	*/
}


#define LARGE_PAGE_SIZE SIZE_2MB
#define PAGE_ALIGN_2MB(Va) ((VOID *)((QWORD)(Va) & ~(LARGE_PAGE_SIZE - 1)))

static QWORD get_ntoskrnl_base(void)
{
	QWORD cr3 = *(QWORD*)(0x10A0);
	QWORD kernel_entry = (QWORD)PAGE_ALIGN_2MB (*(QWORD*)(0x1070)) ;
	for (int i = 0; i < 0x10; i++)
	{
		QWORD entry = kernel_entry - (i * LARGE_PAGE_SIZE);
		QWORD phys  = pm_translate(cr3, entry);
		if (phys && *(unsigned short*)phys == 0x5A4D)
		{
			return entry;
		}
	}
	return 0;
}

BOOLEAN gPatchIsDone;
EFI_HANDLE EfiMainHandlerHandle;

EFI_STATUS EFIAPI EfiMainHandler(
	IN EFI_HANDLE  DispatchHandle,
	IN CONST VOID* Context         OPTIONAL,
	IN OUT VOID* CommBuffer      OPTIONAL,
	IN OUT UINTN* CommBufferSize  OPTIONAL
)
{

        if (!gInOs) {

                EFI_SMM_CPU_PROTOCOL *SmmCpu = NULL;

                if (EFI_ERROR(gSMST->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (VOID **)&SmmCpu)))
                        return 0;

                UINTN cr3;
                if (EFI_ERROR(SmmCpu->ReadSaveState(SmmCpu,
                        sizeof(cr3), EFI_SMM_SAVE_STATE_REGISTER_CR3, gSMST->CurrentlyExecutingCpu, (VOID*)&cr3)))
                        return 0;

                if (cr3 == 0)
                        return 0;

                system_cr3 = *(QWORD*)(0x10A0);
                if (system_cr3 == 0)
                        return 0;

                if (system_cr3 != cr3)
                        return 0;

                ntoskrnl = get_ntoskrnl_base();
                if (ntoskrnl == 0)
                        return 0;

		PsInitialSystemProcess = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsInitialSystemProcess");
                if (PsInitialSystemProcess == 0)
                        return 0;

                QWORD PsGetProcessId = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsGetProcessId");
                QWORD PsGetProcessExitProcessCalled = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsGetProcessExitProcessCalled");
                QWORD PsGetProcessImageFileName = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsGetProcessImageFileName");
                QWORD PsGetProcessWow64Process = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsGetProcessWow64Process");
                QWORD PsGetProcessPeb = vm_get_export_ex(system_cr3, 0, ntoskrnl, "PsGetProcessPeb");

                offset_PsGetProcessExitProcessCalled = *(unsigned int*)(pm_translate(system_cr3, PsGetProcessExitProcessCalled + 2));
                offset_PsGetProcessImageFileName = *(unsigned int*)(pm_translate(system_cr3, PsGetProcessImageFileName + 3));
                offset_ActiveProcessLinks = *(unsigned int*)(pm_translate(system_cr3, PsGetProcessId + 3)) + 8;
                offset_PsGetProcessWow64Process = *(unsigned int*)(pm_translate(system_cr3, PsGetProcessWow64Process + 3));
                offset_PsGetProcessPeb = *(unsigned int*)(pm_translate(system_cr3, PsGetProcessPeb + 3));
                gInOs = 1;
        }

        if (gInOs) {
		if (gPatchIsDone && g_process) {
			if (get_process_by_name("cs2.exe") == g_process)
			{
				vm_write_i32( g_cvar + 0x40, 1 );
				return 0;
			}
			g_cvar = 0;
			gPatchIsDone = 0;
		}

                g_process = get_process_by_name("cs2.exe");
                if (g_process == 0)
                        return EFI_SUCCESS;
                
                g_process_peb = pm_read_i64(pm_translate(system_cr3, g_process + offset_PsGetProcessWow64Process));
                g_process_cr3 = pm_read_i64(pm_translate(system_cr3, g_process + 0x28));
                if (g_process_peb) {
                        g_process_peb = pm_read_i64(pm_translate(system_cr3, g_process_peb));
                        g_process_wow64 = 1;
                } else {
			g_process_peb = pm_read_i64(pm_translate(system_cr3, g_process + offset_PsGetProcessPeb));
			g_process_wow64 = 0;
                }

                if (g_process_peb == 0)
                        return EFI_SUCCESS;

		g_cvar = get_convar("cl_player_proximity_debug");
		if (g_cvar == 0)
			return EFI_SUCCESS;
		
		vm_write_i32( g_cvar + 0x40, 1 );
		
		gPatchIsDone = 1;
        }
        return EFI_SUCCESS;
}

EFI_STATUS EFIAPI EfiMain(IN EFI_LOADED_IMAGE *LoadedImage, IN EFI_SYSTEM_TABLE *SystemTable)
{
	gRT = SystemTable->RuntimeServices;
	gBS = SystemTable->BootServices;
	gST = SystemTable;
		
	EFI_SMM_BASE2_PROTOCOL *gSmmBase2Protocol = 0;
	if (EFI_ERROR(gBS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, 0, (void **)&gSmmBase2Protocol)))
		return 0;
	
	if (EFI_ERROR(gSmmBase2Protocol->GetSmstLocation(gSmmBase2Protocol, &gSMST)))
		return 0;

	EFI_SMM_SW_DISPATCH2_PROTOCOL *gSmmSwDispatch2Protocol = 0;
	if (EFI_ERROR(gSMST->SmmLocateProtocol(&gEfiSmmSwDispatch2ProtocolGuid, 0, (void **)&gSmmSwDispatch2Protocol)))
		return 0;
	
	EFI_SMM_SW_REGISTER_CONTEXT val;
	val.SwSmiInputValue = SW_SMI_VAL;
	
	EFI_HANDLE buf = 0;

	gSmmSwDispatch2Protocol->Register(gSmmSwDispatch2Protocol, (EFI_SMM_HANDLER_ENTRY_POINT2)qword_388, &val, &buf);
        gSMST->SmiHandlerRegister(EfiMainHandler, 0, &EfiMainHandlerHandle);
	return 0;
}

