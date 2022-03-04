#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <intrin.h>
#include "driver.h"
#include "analyze.h"

extern "C" {

NTKERNELAPI CHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

typedef NTSTATUS(__stdcall* PfnMmAccessFault)(ULONG a1, PVOID a2, ULONG a3, ULONG a4);
typedef ULONG(__fastcall* PfnMiAllocateWsle)(ULONG a1, ULONG a2, ULONG a3, ULONG a4,ULONG a5, ULONG a6, ULONG a7);
typedef int(__fastcall* PfnMiCopyOnWriteEx)(ULONG_PTR a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);
typedef int(__fastcall* PfnMiDeletePteRun)(ULONG a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);
typedef int(__fastcall* PfnMiDeleteVirtualAddresses)(ULONG a1, ULONG a2, ULONG a3, ULONG a4, ULONG a5);
typedef  int(__fastcall* PfnMyMiSetProtectionOnSection)(ULONG eproc, ULONG vad, ULONG start_va, ULONG end_va,
	ULONG new_prot, ULONG out_old_prot, ULONG charge, ULONG locked);
typedef void(__fastcall* PfnIopfCompleteRequest)(PVOID a1, ULONG a2);

typedef NTSTATUS(NTAPI *PfnNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG ZeroBits,
	PULONG AllocationSize,
	ULONG AllocationType,
	ULONG Protect);
PfnNtAllocateVirtualMemory origNtAllocateVirtualMemory = NULL;

typedef NTSTATUS(NTAPI *PfnNtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID *BaseAddress,
	PULONG FreeSize,
	ULONG  FreeType);
PfnNtFreeVirtualMemory origNtFreeVirtualMemory = NULL;

PfnZwQueryVirtualMemory   pZwQueryVirtualMemory = NULL;

typedef NTSTATUS(__stdcall* PfnZwProtectVirtualMemory)(HANDLE ProcessHandle,
	PVOID *BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);
PfnZwProtectVirtualMemory pZwProtectVirtualMemory = NULL;

typedef NTSTATUS(__stdcall* PfnZwWriteVirtualMemory)(HANDLE ProcessHandle,
	PVOID BaseAddress, PVOID Buffer, ULONG BufferLength, PULONG ReturnLength);
PfnZwWriteVirtualMemory   pZwWriteVirtualMemory = NULL;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	PVOID          DllBase;
	PVOID          EntryPoint;
	ULONG          SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
	ULONG       Length;
	ULONG       Initialized;
	PVOID       SsHandle;
	LIST_ENTRY  InLoadOrderModuleList;
	LIST_ENTRY  InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	UCHAR                         InheritedAddressSpace;
	UCHAR                         ReadImageFileExecOptions;
	UCHAR                         BeingDebugged;
	UCHAR                         BitField;
	PVOID                         Mutant;
	PVOID                         ImageBaseAddress;
	PPEB_LDR_DATA                 Ldr;
} PEB, *PPEB;

#pragma pack(1)

typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; 
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} SSDT_ENTRY;

typedef struct _IDTENTRY
{
	unsigned short LowOffset;
	unsigned short selector;
	unsigned char  unused_lo;
	unsigned char  segment_type : 4;
	unsigned char  system_segment_flag : 1;
	unsigned char  DPL : 2;
	unsigned char  P : 1;
	unsigned short HiOffset;
} IDTENTRY, *PIDTENTRY;

typedef struct _IDTR {
	USHORT      limit;
	ULONG_PTR   base;
}IDTR, *PIDTR;

typedef struct _SEGMENT_DESC
{
	ULONG LimitLow : 16;
	ULONG BaseLow : 16;
	ULONG BaseHigh1 : 8;
	ULONG SegType : 4;
	ULONG DescType : 1;
	ULONG Dpl : 2;
	ULONG Present : 1;
	ULONG LimitHigh : 4;
	ULONG Avl : 1;
	ULONG Reseverd : 1;
	ULONG DefaultSize : 1;
	ULONG Granularity : 1;
	ULONG BaseHigh2 : 8;
}SEGMENT_DESC, *PSEGMENT_DESC;

typedef struct _GDTR {
	USHORT    Limit;
	ULONG_PTR Base;
}GDTR, *PGDTR;

#pragma pack()

__declspec(dllimport)   SSDT_ENTRY KeServiceDescriptorTable;
#define SYSTEMSERVICE(_index)  KeServiceDescriptorTable.ServiceTableBase[_index]

typedef struct AFD_WSABUF
{
	ULONG len;
	PCHAR buf;
}AFD_WSABUF, *PAFD_WSABUF;

typedef struct AFD_INFO
{
	PAFD_WSABUF    BufferArray;
	ULONG BufferCount;
	ULONG AfdFlags;
	ULONG TdiFlags;
}AFD_INFO, *PAFD_INFO;

typedef NTSTATUS(NTAPI *PfnNtReadFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);
PfnNtReadFile        origNtReadFile = NULL;
ULONG           gNtReadFileCount = 0;
typedef   NTSTATUS(NTAPI *PfnNtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
	);
PfnNtWriteFile        origNtWriteFile = NULL;
ULONG           gNtWriteFileCount = 0;

typedef  NTSTATUS(NTAPI *PfnNtDeviceIoControlFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength
	);
PfnNtDeviceIoControlFile origNtDeviceIoControlFile = NULL;
ULONG           gNtDeviceIoCount = 0;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef  NTSTATUS(NTAPI * PfnKeInitializeApc)(
	PKAPC Apc,
	PETHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PVOID KernelRoutine,  //PKKERNEL_ROUTINE
	PVOID RundownRoutine, //PKRUNDOWN_ROUTINE
	PVOID NormalRoutine,  //PKNORMAL_ROUTINE
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
	);
PfnKeInitializeApc KeInitializeApc = NULL;

typedef BOOLEAN(NTAPI * PfnKeInsertQueueApc)(
	IN PRKAPC Apc,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2,
	IN KPRIORITY Increment
	);
PfnKeInsertQueueApc KeInsertQueueApc = NULL;

//function hook
ULONG   g_MmAccessFault = NULL;
PVOID   g_TrampoMmAccessFault = NULL;
ULONG   g_MiAllocateWsle = NULL;
PVOID   g_TrampoMiAllocateWsle = NULL;
ULONG   g_MiCopyOnWriteEx = NULL;
PVOID   g_TrampoMiCopyOnWriteEx = NULL;
ULONG   g_MiDeletePteRun = NULL;
PVOID   g_TrampoMiDeletePteRun = NULL;
ULONG   g_MiDeleteVirtualAddresses = NULL;
PVOID   g_TrampoMiDeleteVirtualAddresses = NULL;
ULONG   g_MiSetProtectionOnSection = NULL;
PVOID   g_TrampoMiSetProtectionOnSection = NULL;

ULONG   g_MmPfnDatabase = 0;
UINT32  g_kitrap0e = 0;
//syscall
ULONG   g_KiFastCallEntry = NULL;
PVOID   g_TrampoKiFastCallEntry = NULL;
ULONG   g_KiServiceExit = NULL;
PVOID   g_TrampoKiServiceExit = NULL;
ULONG   g_Kei386HelperExit = NULL;
PVOID   g_TrampoKei386HelperExit = NULL;
ULONG   g_KiCallUserModeExit = NULL;
PVOID   g_TrampoKiCallUserModeExit = NULL;

//teb
ULONG   g_MmCreateTeb = NULL;
ULONG   g_MmCreateTebBack = NULL;
PVOID   g_TrampoMmCreateTeb = NULL;
ULONG   g_PspAllocateThread = NULL;
ULONG   g_PspAllocateThreadBack = NULL;
PVOID   g_TrampoPspAllocateThread = NULL;
//context
ULONG   g_SwapContext = NULL;
LONG64  g_SwapContextBytes = 0;
ULONG   g_SwapContextBack = NULL;
//io
ULONG   g_IopfCompleteRequest = NULL;
PVOID   g_TrampoIopfCompleteRequest = NULL;

//process
ULONG       g_process_init_code_va[16] = { 0 };
ULONG64     g_process_init_code_pa[16] = { 0 };
ULONG       g_init_code_num = 0;
ULONG       g_process_init_map_va[16] = { 0 };
ULONG64     g_process_init_map_pa[16] = { 0 };
ULONG       g_init_map_num = 0;

HANDLE  g_target_pid = (HANDLE)-1;
ULONG   g_target_cr3 = 0;
PVOID   g_target_eprocess = NULL;
ULONG   g_start_time, g_exit_time;
bool    g_target_active = false;

ULONG   g_ntdll_base = 0;
ULONG   g_kernel_base = 0;
ULONG   g_user32_base = 0;
ULONG   g_debug_base = 0;

ULONG   g_modulesCount = 0;
ULONG   g_threadCreateCount = 0;
ULONG   g_threadExitCount = 0;

PROCESSOR_DATA *g_processorList[8] = { 0 };
PDEVICE_OBJECT   g_pDeviceObj = NULL;

//preallocation
KGUARDED_MUTEX  g_allocMutex;
PVOID       g_allocSlots[MAX_ALLOCATE_NUMBER] = { 0 };
PMDL        g_allocSlotsMdl[MAX_ALLOCATE_NUMBER] = { 0 };
ULONG       g_allocCount = 0;
PVOID       g_allocBase = NULL;
PVOID       g_allocPtr = NULL;

//analysis
PVOID      *g_codeTable = NULL;
PMDL        g_codeTableMdl = NULL;
ULONG64    *g_pageState = NULL;

ULONG       g_auxPageBase = NULL;

//case study
ULONG       g_taintSourceCount = 0;
ULONG       g_taint_set = 0;
ULONG       g_send_count = 0;
ULONG       g_write_count = 0;
ULONG       g_recv_bytes = 4 * 1024;  //4k
ULONG       g_read_bytes = 4 * 1024; 

//analysis state
PVOID      *g_stateTable = NULL;
PMDL        g_stateTableMdl = NULL;
PVOID       g_allocStateBase[CACHE_MEM_STATE_NUM] = { 0 };
PMDL        g_allocStateMdl[CACHE_MEM_STATE_NUM] = { 0 };
ULONG       g_allocStateCount = 0;

PVOID          *g_entry_table = NULL;
LIST_ENTRY     g_entries_list;
KSPIN_LOCK     g_entries_lock;
PVOID          g_entries_base = NULL;
PVOID          g_entries_ptr = NULL;
ULONG          g_sb_alloc_count = 0;
ULONG          g_sb_free_count = 0;

//test
ULONG               g_sb_overflow_count = 0;
STATE_BUFFER_ENTRY *g_overflow_entry = NULL;
ULONG               g_debug_flag = 0;

//counter
ULONG64		g_ExecCount = 0;
ULONG64		g_ExecCount1 = 0;
ULONG64		g_ExecCount2 = 0;
ULONG64		g_ExecCount3 = 0;
ULONG64     g_totalCounter[9] = { 0 };


int __cdecl __stdio_common_vsprintf(
	_In_ unsigned __int64 _Options,
	_Out_writes_opt_z_(_BufferCount) char *_Buffer, _In_ size_t _BufferCount,
	_In_z_ _Printf_format_string_params_(2) char const *_Format,
	_In_opt_ _locale_t _Locale, va_list _ArgList) {
	UNREFERENCED_PARAMETER(_Options);
	UNREFERENCED_PARAMETER(_Locale);

	// Calls _vsnprintf exported by ntoskrnl
	using _vsnprintf_type = int __cdecl(char *, size_t, const char *, va_list);
	static _vsnprintf_type *local__vsnprintf = nullptr;
	if (!local__vsnprintf) {
		UNICODE_STRING proc_name_U = {};
		RtlInitUnicodeString(&proc_name_U, L"_vsnprintf");
		local__vsnprintf = reinterpret_cast<_vsnprintf_type *>(
			MmGetSystemRoutineAddress(&proc_name_U));
	}
	return local__vsnprintf(_Buffer, _BufferCount, _Format, _ArgList);
}

ULONG QueryTimeMillisecond()
{
	LARGE_INTEGER CurTime, Freq;
	CurTime = KeQueryPerformanceCounter(&Freq);
	return (ULONG)((CurTime.QuadPart * 1000) / Freq.QuadPart);
}

NTSTATUS ExecuteOnAllProcessors(NTSTATUS(*callback)(void *), void *context) 
{
	const auto cpuCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG index = 0; index < cpuCount; index++) 
	{
		PROCESSOR_NUMBER processorNum = {};
		auto status =
			KeGetProcessorNumberFromIndex(index, &processorNum);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}
		GROUP_AFFINITY affinity = {};
		affinity.Group = processorNum.Group;
		affinity.Mask = 1ull << processorNum.Number;
		GROUP_AFFINITY prevAffinity = {};
		KeSetSystemGroupAffinityThread(&affinity, &prevAffinity);

		status = callback(context);

		KeRevertToUserGroupAffinityThread(&prevAffinity);
		if (!NT_SUCCESS(status)) 
		{
			return status;
		}
	}
	return STATUS_SUCCESS;
}

void ApcKernelRoutine(IN struct _KAPC *Apc,
	IN OUT PVOID *NormalRoutine,
	IN OUT PVOID *NormalContext,
	IN OUT PVOID *SystemArgument1,
	IN OUT PVOID *SystemArgument2)
{
}

PVOID  AllocateFromUserspace(HANDLE pid, SIZE_T size)
{
	HANDLE            hProcess;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	CLIENT_ID         ClientId = { 0 };
	ClientId.UniqueProcess = pid;

	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[CHECK] ZwOpenProcess Error -- %#X\n", status);
		return 0;
	}
	SIZE_T ReginSize = size;
	PVOID  allocBase = 0;
	ULONG  allocType = MEM_COMMIT;

	status = ZwAllocateVirtualMemory(hProcess, &allocBase, 0, &ReginSize, allocType, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[CHECK] ZwAllocateVirtualMemory Error -- %#X\n", status);
		ZwClose(hProcess);
		return 0;
	}

	ZwClose(hProcess);
	return allocBase;
}

PVOID AllocateFromUserSpaceCache(SIZE_T size)
{
	PVOID allocAddr = NULL;

	KeAcquireGuardedMutex(&g_allocMutex);

	if (((ULONG_PTR)g_allocPtr + size) > ((ULONG_PTR)g_allocBase + CACHE_CODE_MAP_SIZE))
	{
		DbgPrint("AllocateFromUserSpaceCache, space is not enough, g_allocPtr %x.\n", g_allocPtr);
		__debugbreak();

		KeReleaseGuardedMutex(&g_allocMutex);
		ZwTerminateProcess(NtCurrentProcess(), 1);
	}
	allocAddr = g_allocPtr;
	g_allocPtr = (PVOID)((ULONG_PTR)g_allocPtr + size);

	KeReleaseGuardedMutex(&g_allocMutex);

	return allocAddr;
}

VOID  ModifyExecutablePageEntry(ULONG  pte, ULONG va, ULONG64 pa)
{
	ULONG  vpfn = va >> 12;
	PVOID  codePage = g_codeTable[vpfn];
	if (((ULONG)codePage & 0xFFF00000) == ANALYSIS_CODE_FAULT_BASE)
	{
		codePage = AllocateFromUserSpaceCache(PAGE_SIZE * 4);
		for (ULONG i = 0; i < PAGE_SIZE; i++)
		{
			((PULONG)codePage)[i] = (va & 0xFFFFF000) + i; //Point to itself by default 
		}
		g_codeTable[vpfn] = (PVOID)((ULONG)codePage & 0xFFFFF000);
	}

	//£¨byte3:pte_nx£¬byte2:pte_write£¬byte1:written£¬byte0:executed£©
	*(UCHAR *)((UCHAR *)&g_pageState[vpfn] + 2) = (UCHAR)((pa >> 1) & 1);
	*(UCHAR *)((UCHAR *)&g_pageState[vpfn] + 3) = 0;

	pa = pa | (1LL << 63); //XD = 1
	*(ULONG64 *)pte = pa;
	__invlpg((PVOID)va);
}

NTSTATUS IoctlCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IoctlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;        
	NTSTATUS            status = STATUS_SUCCESS;
	ULONG               inBufLength;  
	ULONG               outBufLength; 
	PVOID               inBuf, outBuf; 

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	inBuf = Irp->AssociatedIrp.SystemBuffer;
	outBuf = Irp->AssociatedIrp.SystemBuffer;

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_KANALYZER_THREAD_START:
		DbgPrint("IOCTL_KANALYZER_THREAD_START.\n");
		Irp->IoStatus.Information = 0;
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("Unknown ioctl %x\n", irpSp->Parameters.DeviceIoControl.IoControlCode);
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

VOID LoadImageNotifyCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO pImageInfo)
{
	WCHAR               pwDupName[260];

	if (!FullImageName || !FullImageName->Length || ProcessId == (HANDLE)0 ||
		ProcessId == (HANDLE)4 || pImageInfo->SystemModeImage)
		return;
	if (g_target_pid == ProcessId)
	{
		g_modulesCount++;
		DbgPrint("[Module] Base: %x, Image: %wZ\n", pImageInfo->ImageBase, FullImageName);

		memcpy(pwDupName, FullImageName->Buffer, FullImageName->Length);
		WCHAR *pwlwrDupName = _wcslwr(pwDupName);
		if (0 == _wcsnicmp(FullImageName->Buffer, L"\\SystemRoot\\System32\\ntdll.dll", sizeof("\\SystemRoot\\System32\\ntdll.dll") * 2))
		{
			g_ntdll_base = (ULONG)pImageInfo->ImageBase;
		}
		else if (wcsstr(pwlwrDupName, L"\\system32\\user32.dll"))
		{
			g_user32_base = (ULONG)pImageInfo->ImageBase;
		}
		else if (wcsstr(pwlwrDupName, L"\\system32\\kernelbase.dll"))
		{
			g_kernel_base = (ULONG)pImageInfo->ImageBase;
		}	
	}
}

NTSTATUS OutputProcessorCounter(void *context)
{
	ULONG cpu_num = KeGetCurrentProcessorNumber();
	PROCESSOR_DATA *processorData = g_processorList[cpu_num];

	ULONG bufUsed = processorData->BufPtr - processorData->BufBase;
	DbgPrint("[%d] c0: %llu,c1: %llu,c2: %llu,c3: %llu,c4: %llu,c5: %llu,c6: %llu,c7: %llu,bufUsed: %u.\n",
		KeGetCurrentProcessorNumberEx(nullptr),
		processorData->Counter0,
		processorData->Counter1,
		processorData->Counter2,
		processorData->Counter3,
		processorData->Counter4,
		processorData->Counter5,
		processorData->Counter6,
		processorData->Counter7,
		bufUsed);

	g_totalCounter[0] += processorData->Counter0;
	g_totalCounter[1] += processorData->Counter1;
	g_totalCounter[2] += processorData->Counter2;
	g_totalCounter[3] += processorData->Counter3;
	g_totalCounter[4] += processorData->Counter4;
	g_totalCounter[5] += processorData->Counter5;
	g_totalCounter[6] += processorData->Counter6;
	g_totalCounter[7] += processorData->Counter7;
	g_totalCounter[8] += bufUsed;

	//Unlock
	MmUnlockPages(processorData->BufMdl);
	IoFreeMdl(processorData->BufMdl);

	//Free
	HANDLE            hProcess;
	OBJECT_ATTRIBUTES ObjAttr = { 0 };
	CLIENT_ID         ClientId = { 0 };
	ClientId.UniqueProcess = context;
	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("OutputProcessorCounter ZwOpenProcess Error -- %#X", status);
		ZwClose(hProcess);
		return 0;
	}
	SIZE_T ReginSize = 0;
	ZwFreeVirtualMemory(hProcess, (PVOID*)&processorData->BufBase, &ReginSize, MEM_RELEASE);
	ZwClose(hProcess);

	return STATUS_SUCCESS;
}

NTSTATUS  InitProcessor(void *context)
{
	HANDLE pid = (HANDLE)context;

	ULONG cpu_num = KeGetCurrentProcessorNumber();
	PROCESSOR_DATA *processorData = g_processorList[cpu_num];

	PVOID allocBase = AllocateFromUserspace(pid, PER_CPU_ALLOCATE_SIZE);
	processorData->BufBase = (ULONG)allocBase;
	processorData->BufPtr = processorData->BufBase;
	
	//For easy access£¬lock
	KAPC_STATE kApc;
	PEPROCESS  pEprocess;
	PsLookupProcessByProcessId(pid, &pEprocess);
	KeStackAttachProcess(pEprocess, &kApc);
	processorData->BufMdl = IoAllocateMdl(allocBase, PER_CPU_ALLOCATE_SIZE, FALSE, FALSE, NULL);
	__try 
	{
		MmProbeAndLockPages(processorData->BufMdl, UserMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Lock BufMdl error code = %x", GetExceptionCode());
		__debugbreak();
	}

	for (ULONG pg = 0; pg < PER_CPU_ALLOCATE_SIZE; pg += PAGE_SIZE)
	{
		ULONG  va = (ULONG)allocBase + pg;
		*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1;
	}

	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);

	processorData->HdBufBase = (ULONG)allocBase + PER_CPU_CODE_BUF_SIZE;
	processorData->HdBufPtr = processorData->HdBufBase;
	processorData->TmpBufBase = (ULONG)allocBase + PER_CPU_CODE_BUF_SIZE + PER_CPU_HEAD_BUF_SIZE;
	processorData->TmpBufPtr = processorData->TmpBufBase;

	DbgPrint("[Allocation] Processors. Index %d, BufBase %08x, HdBufBase %08x, TmpBufBase %08x.\n",
		cpu_num, processorData->BufBase, processorData->HdBufBase, processorData->TmpBufBase);

	return STATUS_SUCCESS;
}

void GetExistingPages(ULONG_PTR  cr3_pa)
{
	ULONG64 pdpt_va[2];
	PULONG64 pd_mapped_va = NULL;
	PULONG64 pt_mapped_va = NULL;
	PHYSICAL_ADDRESS PhysicalAddress;
	PhysicalAddress.QuadPart = cr3_pa;
	g_target_cr3 = cr3_pa;

	PULONG64 pMappedVa = (PULONG64)MmMapIoSpace(PhysicalAddress, 0x10, MmNonCached);
	if (!pMappedVa)
	{
		DbgPrint("GetExistingPages error, pdpt\n");
		return;
	}
	RtlCopyMemory(pdpt_va, pMappedVa, 0x10);
	MmUnmapIoSpace(pMappedVa, 0x10);

	//PDPTE, bits 31:30, 3-level. PAE£¬start at 0xC0600000
	for (ULONG i = 0; i < 2; i++) 
	{
		if (pdpt_va[i] & 0x1ull) 
		{
			ULONG64 pd_pa = pdpt_va[i] & 0x7FFFFFFFFFFFF000ull;
			PhysicalAddress.QuadPart = pd_pa;
			pd_mapped_va = (PULONG64)MmMapIoSpace(PhysicalAddress, PAGE_SIZE, MmNonCached);
			if (!pd_mapped_va)
			{
				DbgPrint("GetExistingPages error, pd\n");
				return;
			}
			DbgPrint("PDPTE paddr: %llx\n", pd_pa);
			for (ULONG j = 0; j < 512; j++) 
			{
				if (pd_mapped_va[j] & 0x1ull)
				{
					ULONG64 pt_pa = pd_mapped_va[j] & 0x7FFFFFFFFFFFF000ull;
					PhysicalAddress.QuadPart = pt_pa;
					pt_mapped_va = (PULONG64)MmMapIoSpace(PhysicalAddress, PAGE_SIZE, MmNonCached);
					if (!pt_mapped_va)
					{
						DbgPrint("GetExistingPages error, pt\n");
						return;
					}
					DbgPrint(" [%x] PDE paddr: %llx\n", j, pt_pa);
					ULONG k_max = 512;
					if ((i == 1) && (j == 511)) //Skip shared user data£¬ 0x7ffe0000<->0xffdf0000
					{
						k_max = 480;
					}
					for (ULONG k = 0; k < k_max; k++)
					{
						ULONG64 page_4k_pa = pt_mapped_va[k];
						if (page_4k_pa & 0x1ull)
						{				
							ULONG   vpfn = (i << 18) + (j << 9) + k;
							DbgPrint("  [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
							g_process_init_map_va[g_init_map_num] = vpfn;
							g_process_init_map_pa[g_init_code_num] = page_4k_pa;
							g_init_map_num++;
							if (!(page_4k_pa >> 63)) //NX-
							{
								g_process_init_code_va[g_init_code_num] = vpfn;
								g_process_init_code_pa[g_init_code_num] = page_4k_pa;
								g_init_code_num++;
								DbgPrint("  Execute [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
							}
						}
					}
					for (ULONG k = k_max; k < 512; k++)
					{
						ULONG64 page_4k_pa = pt_mapped_va[k];
						if (page_4k_pa & 0x1ull)
						{	
							ULONG   vpfn = (i << 18) + (j << 9) + k;
							g_process_init_map_va[g_init_map_num] = vpfn;
							g_init_map_num++;
							DbgPrint("  Special [%x] PTE va: %x, paddr: %llx.\n", k, vpfn << 12, page_4k_pa);
						}
					}
					MmUnmapIoSpace(pt_mapped_va, PAGE_SIZE);
				}
			}
			MmUnmapIoSpace(pd_mapped_va, PAGE_SIZE);
		}
	}
}

PVOID AllocateFromUserSpaceBufferEntries(ULONG va)
{
	PVOID alloc_va = NULL;

	STATE_BUFFER_ENTRY *entry = (STATE_BUFFER_ENTRY *)ExInterlockedRemoveHeadList(&g_entries_list, &g_entries_lock);
	if (entry == NULL)
	{
		//For the case of insufficient space, further processing is required

		entry = g_overflow_entry; //ignored
		g_sb_overflow_count++;

		//__debugbreak();
	}
	alloc_va = entry->Address;

	InterlockedExchange((LONG *)&g_entry_table[va >> 12], (LONG)entry);
	g_sb_alloc_count++;

	return alloc_va;
}

VOID DeallocateUserSpaceBufferEntries(ULONG vfn)
{
	STATE_BUFFER_ENTRY *entry = (STATE_BUFFER_ENTRY *)g_entry_table[vfn];
	if (entry)
	{
		if (entry != g_overflow_entry) //ignored
		{
			InterlockedExchange((LONG *)&g_entry_table[vfn], 0);
			ExInterlockedInsertTailList(&g_entries_list, &entry->ListEntry, &g_entries_lock);
		}	
		g_sb_free_count++;
	}
}

ULONG __stdcall MyMmCreateTebHandler(PEPROCESS eprocess)
{
	if (!g_target_eprocess)
	{
		CHAR *pProcName = PsGetProcessImageFileName(eprocess);

		//Add test programs
		if (!_strnicmp(pProcName, "7z.exe", 7) || !_strnicmp(pProcName, "whoami.exe", 11) ||
			!_strnicmp(pProcName, "systeminfo.exe", 15))  
		{
			g_target_eprocess = eprocess;
			return 1;
		}
	}
	else if (g_target_eprocess == eprocess)
	{
		return 2;
	}

	return 0;
}

void ProcessNotifyRoutineEx(
	PEPROCESS pEprocess,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	NTSTATUS  status;
	
	CHAR *pProcName = PsGetProcessImageFileName(pEprocess);

	if (g_target_eprocess == pEprocess)
	{
		if (CreateInfo != NULL)
		{
			ULONG  ulPhyDirBase = *(ULONG *)((PCHAR)pEprocess + PD_EPROCESS_OFFSET);
			
			KAPC_STATE kApc;
			KeStackAttachProcess(pEprocess, &kApc);
			GetExistingPages(ulPhyDirBase);
			KeUnstackDetachProcess(&kApc);

			status = ExecuteOnAllProcessors(InitProcessor, ProcessId);
			if (NT_SUCCESS(status))
			{
				DbgPrint("InitProcessor success.\n");
			}
			else
			{
				DbgPrint("InitProcessor error %x.\n", status);
			}

			//Init
			g_entries_base = ExAllocatePoolWithTag(NonPagedPool, BUFFER_ENTRY_SIZE, KANALYZER_POOL_TAG);
			if (!g_entries_base)
			{
				DbgPrint("ExAllocatePoolWithTag g_entries_base error (%08x).", status);
			}
			g_entry_table = (PVOID *)ExAllocatePoolWithTag(NonPagedPool, CODE_TABLE_SIZE, KANALYZER_POOL_TAG);
			if (!g_entry_table)
			{
				DbgPrint("ExAllocatePoolWithTag g_entry_table error (%08x).", status);
			}
			memset(g_entry_table, 0, 0x80000 * 4);
			g_entries_ptr = g_entries_base;
			InitializeListHead(&g_entries_list);
			KeInitializeSpinLock(&g_entries_lock);

			//Attach
			KeStackAttachProcess(pEprocess, &kApc);
		
			//Pre-allocation
			g_codeTable = (PVOID *)AllocateFromUserspace(ProcessId, CODE_TABLE_SIZE);
			for (ULONG i = 0; i < CODE_TABLE_SIZE; i += PAGE_SIZE)
			{
				ULONG va = (ULONG)g_codeTable + i;
				*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1;
			}
			for (ULONG i = 0; i < CODE_TABLE_SIZE/4; i++)
			{
				((PULONG)g_codeTable)[i] = ANALYSIS_CODE_FAULT_BASE + i;
			}
			//Lock
			g_codeTableMdl = IoAllocateMdl(g_codeTable, CODE_TABLE_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(g_codeTableMdl, UserMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Lock codeTableMdl error code = %x", GetExceptionCode());
				__debugbreak();
			}

			g_stateTable = (PVOID *)AllocateFromUserspace(ProcessId, CODE_TABLE_SIZE);
			for (ULONG i = 0; i < CODE_TABLE_SIZE; i += PAGE_SIZE)
			{
				ULONG va = (ULONG)g_stateTable + i;
				*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1;
			}
			for (ULONG vfn = 0; vfn < 0x80000; vfn++)
			{
				g_stateTable[vfn] = (PVOID)ANALYSIS_STATE_INIT_VALUE;
			}
			g_stateTableMdl = IoAllocateMdl(g_stateTable, CODE_TABLE_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(g_stateTableMdl, UserMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Lock stateTableMdl error code = %x", GetExceptionCode());
				__debugbreak();
			}

			g_allocBase = (PVOID *)AllocateFromUserspace(ProcessId, CACHE_CODE_MAP_SIZE);
			for (ULONG i = 0; i < CACHE_CODE_MAP_SIZE; i += PAGE_SIZE)
			{
				ULONG va = (ULONG)g_allocBase + i;
				*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1;
			}
			memset(g_allocBase, 0, CACHE_CODE_MAP_SIZE);
			g_allocSlots[0] = g_allocBase;
			g_allocCount = 1;
			g_allocPtr = g_allocBase;
			//lock
			g_allocSlotsMdl[0] = IoAllocateMdl(g_allocBase, CACHE_CODE_MAP_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(g_allocSlotsMdl[0], UserMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Lock allocBase error code = %x", GetExceptionCode());
				__debugbreak();
			}
			
			ULONG entry_count = 0;
			for (ULONG i = 0; i < CACHE_MEM_STATE_NUM; i++)
			{
				//Virtual addresses are not consecutive
				PVOID localAllocBase = (PVOID *)AllocateFromUserspace(ProcessId, CACHE_MEM_STATE_SIZE);
				memset(localAllocBase, 0, CACHE_MEM_STATE_SIZE);
				g_allocStateBase[g_allocStateCount++] = localAllocBase;

				//case1, one page
				for (ULONG size = 0; size < (CACHE_MEM_STATE_SIZE - PAGE_SIZE); size += PAGE_SIZE)
				{
					STATE_BUFFER_ENTRY *node = (STATE_BUFFER_ENTRY *)g_entries_ptr;
					node->Address = (PVOID)((ULONG)localAllocBase + size);
					InsertTailList(&g_entries_list, &node->ListEntry);
					g_entries_ptr = (PVOID)((ULONG)g_entries_ptr + sizeof(STATE_BUFFER_ENTRY));
					entry_count++;
				
					ULONG va = (ULONG)node->Address;
					*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1;
				}
				//case2, add a guard page
				//for (ULONG size = 0; size < (CACHE_MEM_STATE_SIZE - 2 * PAGE_SIZE); size += 2 * PAGE_SIZE)
				//{
				//	STATE_BUFFER_ENTRY *node = (STATE_BUFFER_ENTRY *)g_entries_ptr;
				//	node->Address = (PVOID)((ULONG)localAllocBase + size);
				//	InsertTailList(&g_entries_list, &node->ListEntry);
				//	g_entries_ptr = (PVOID)((ULONG)g_entries_ptr + sizeof(STATE_BUFFER_ENTRY));
				//	entry_count++;

				//	ULONG va = (ULONG)node->Address;
				//	*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 1; 

				//	//GUARD_PAGE
				//	va += PAGE_SIZE;
				//	*(ULONG *)((ULONG *)&g_pageState[va >> 12] + 1) = 0x11;
				//	ULONG   pte = 0xC0000000 + (((ULONG)va >> 9) & 0x7ffff8);
				//	*(ULONG *)pte &= 0xFFFFFFFB;  //u/s = 0
				//	__invlpg((PVOID)va);
				//}
				////DbgPrint("[Allocation] State cache, base %x, size %x\n", localAllocBase, CACHE_MEM_STATE_SIZE);
			}
			g_overflow_entry = (STATE_BUFFER_ENTRY *)RemoveHeadList(&g_entries_list);

			DbgPrint("[Preallocation] CODE: cache_base %08x, size %x. STATE: buffer_entries %u, cache_size %x, %u\n", 
				g_allocBase, CACHE_CODE_MAP_SIZE, entry_count, CACHE_MEM_STATE_SIZE, CACHE_MEM_STATE_NUM);

			for (ULONG i = 0; i < g_init_map_num; i++)
			{
				ULONG   vfn = g_process_init_map_va[i];
				ULONG   va = vfn << 12;
				ULONG64 pa = g_process_init_map_pa[i];
				ULONG allocVa = (ULONG)AllocateFromUserSpaceBufferEntries(va);
				g_stateTable[vfn] = (PVOID)(allocVa - va);
				DbgPrint("%d, init all. va %08x, pa %016llx, allocVa %08x\n", i, va, pa, allocVa);
			}
			for (ULONG i = 0; i < g_init_code_num; i++)
			{
				ULONG   vfn = g_process_init_code_va[i];
				ULONG   va = vfn << 12;
				ULONG64 pa = g_process_init_code_pa[i];
				ULONG   pte = 0xC0000000 + (((ULONG)va >> 9) & 0x7ffff8);
				ModifyExecutablePageEntry(pte, va, pa);
				DbgPrint("%d, init execute. pte %x, va %08x, pa %016llx, page_state %08x\n",
					i, pte, va, pa, g_pageState[vfn]);
			}
			//aux
			PROCESSOR_DATA *processorData = g_processorList[KeGetCurrentProcessorNumber()];
			g_auxPageBase = processorData->BufPtr;
			processorData->BufPtr += PAGE_SIZE;

			//Detach
			KeUnstackDetachProcess(&kApc);

			g_target_active = true;
			g_target_pid = ProcessId;
			//g_target_eprocess = pEprocess;
			g_target_cr3 = ulPhyDirBase;
			g_start_time = QueryTimeMillisecond();

			LARGE_INTEGER currTime;
			LARGE_INTEGER localTime;
			TIME_FIELDS  timeFields;
			KeQuerySystemTime(&currTime);
			ExSystemTimeToLocalTime(&currTime, &localTime);
			RtlTimeToTimeFields(&localTime, &timeFields);

			DbgPrint("\nTarget process create, Time(ms): %u, %u:%u:%u, pid 0x%x, EPROCESS %x, name %s, allocBase %x, codeTable %x, auxBase %x.\n",
				g_start_time, timeFields.Hour, timeFields.Minute, timeFields.Milliseconds, 
				ProcessId, pEprocess, pProcName, g_allocBase, g_codeTable, g_auxPageBase);

			//__debugbreak(); //debug
		}
		else
		{
			g_target_active = false;

			g_exit_time = QueryTimeMillisecond();
			DbgPrint("\nTarget process exit, name %s, Time(ms): %u, elapsed %u , threads %d, modules %d,\n", 
				pProcName, g_exit_time, g_exit_time - g_start_time, g_threadCreateCount, g_modulesCount);
	
			//__debugbreak(); //debug

			//Release
			ULONG tableCount = 0;
			if (g_codeTable)
			{
				tableCount = 0;
				for (ULONG i = 0; i < 0x80000; i++)
				{
					//if ((ULONG)g_codeTable[i] != NULL)
					if (((ULONG)g_codeTable[i] & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
					{
						tableCount++;
					}
				}
				//Unlock
				MmUnlockPages(g_codeTableMdl);
				IoFreeMdl(g_codeTableMdl);
				SIZE_T ReginSize = 0;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_codeTable, &ReginSize, MEM_RELEASE);
				DbgPrint(" Free codeTable, mapped page %d\n", tableCount);
			}
			if (g_stateTable)
			{
				tableCount = 0;
				for (ULONG i = 0; i < 0x80000; i++)
				{
					if ((ULONG)g_stateTable[i] != ANALYSIS_STATE_INIT_VALUE)
					{
						tableCount++;
					}
				}
				//Unlock
				MmUnlockPages(g_stateTableMdl);
				IoFreeMdl(g_stateTableMdl);
				SIZE_T ReginSize = 0;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_stateTable, &ReginSize, MEM_RELEASE);
				DbgPrint(" Free stateTable, mapped page %d\n", tableCount);
			}

			//Free
			status = ExecuteOnAllProcessors(OutputProcessorCounter, g_target_pid);
			if (NT_SUCCESS(status)) {
				DbgPrint("OutputProcessorCounter success.\n");
			}
			else {
				DbgPrint("OutputProcessorCounter error, %x.\n", status);
			}
			DbgPrint(" Total. c0: %llu, c1: %llu, c2: %llu, c3: %llu, c4: %llu, c5: %llu, c6: %llu, c7: %llu, buf_used: %llu\n",
				g_totalCounter[0], g_totalCounter[1], g_totalCounter[2], 
				g_totalCounter[3], g_totalCounter[4], g_totalCounter[5],
				g_totalCounter[6], g_totalCounter[7], g_totalCounter[8]);

			DbgPrint(" Execution count. %llu, %llu, %llu, %llu, alloc count %u, %u, %u\n\n", 
				g_ExecCount, g_ExecCount1, g_ExecCount2, g_ExecCount3, 
				g_sb_alloc_count, g_sb_free_count, g_sb_overflow_count);

			for (ULONG i = 0; i < g_allocCount; i++)
			{
				MmUnlockPages(g_allocSlotsMdl[i]);
				IoFreeMdl(g_allocSlotsMdl[i]);
				SIZE_T ReginSize = CACHE_CODE_MAP_SIZE;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_allocSlots[i], &ReginSize, MEM_RELEASE);
			}
			for (ULONG i = 0; i < g_allocStateCount; i++)
			{
				SIZE_T ReginSize = CACHE_MEM_STATE_SIZE;
				ZwFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&g_allocStateBase[i], &ReginSize, MEM_RELEASE);
			}

			g_target_cr3 = 0;
			g_target_pid = (HANDLE)-1;
			g_target_eprocess = NULL;
		}
	}
}

VOID CreateThreadNotifyRoutineEx(
	HANDLE ProcessId,
	HANDLE ThreadId,
	BOOLEAN Create)
{
	if (g_target_pid == ProcessId)
	{
		THREAD_DATA  *pThreadData = NULL;
		PETHREAD      pThread = PsGetCurrentThread();
		PUCHAR        pTeb = (PUCHAR)*(ULONG *)((PUCHAR)pThread + TEB_OFFSET);
		if (Create)  
		{
			pThreadData = (THREAD_DATA *)ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_DATA), KANALYZER_POOL_TAG);
			if (!pThreadData)
			{
				DbgPrint("[CHECK] Thread created, allocate error.\n");
				return;
			}
			RtlZeroMemory(pThreadData, sizeof(THREAD_DATA));
		
			pThreadData->Start = 1;
			pThreadData->Pid = (ULONG)ProcessId;
			pThreadData->Tid = (ULONG)ThreadId;
			pThreadData->Teb = (ULONG)pTeb;

			*(ULONG *)(pTeb + TEB_AUX_PAGE_BASE_OFFSET) = g_auxPageBase;
			*(ULONG *)(pTeb + TEB_LOCAL_BUFFER_BASE_OFFSET) = (ULONG)pTeb + TEB_RECORD_SLOT_OFFSET;

			InterlockedIncrement((LONG *)&g_threadCreateCount);

			DbgPrint("*[ThreadNotifyRoutine] Create %d, ThreadData %x, TEB %x, ETHREAD %x, Buffer %x\n", 
				ThreadId, pThreadData, pTeb, pThread, pThreadData->RecordBuffer);

			//Extended space
			*(ULONG *)(pTeb + PAGE_SIZE) = 0;
			pThreadData->TebExtendMdl = IoAllocateMdl(pTeb + PAGE_SIZE, PAGE_SIZE, FALSE, FALSE, NULL);
			__try
			{
				MmProbeAndLockPages(pThreadData->TebExtendMdl, UserMode, IoWriteAccess);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("Lock TebExtendMdl error code = %x", GetExceptionCode());
				__debugbreak();
			}
			*(ULONG_PTR *)((PUCHAR)pThread + THREAD_DATA_OFFSET) = (ULONG_PTR)pThreadData;
		}
		else
		{
			DbgPrint("@[ThreadNotifyRoutine] Exit. %d, time %u.\n", ThreadId, QueryTimeMillisecond());
			
			pThreadData = (THREAD_DATA *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + THREAD_DATA_OFFSET);
			if (pThreadData)
			{
				//DEBUG
				g_ExecCount += *(ULONG64 *)(pThreadData->Teb + TEB_COUNTER_SLOT_OFFSET);
				g_ExecCount1 += *(ULONG64 *)(pThreadData->Teb + TEB_COUNTER_SLOT_OFFSET + 8);
				g_ExecCount2 += *(ULONG64 *)(pThreadData->Teb + TEB_COUNTER_SLOT_OFFSET + 16);
				g_ExecCount3 += *(ULONG64 *)(pThreadData->Teb + TEB_COUNTER_SLOT_OFFSET + 24);
				//Unlock
				MmUnlockPages(pThreadData->TebExtendMdl);
				IoFreeMdl(pThreadData->TebExtendMdl);
				if (pThreadData->RecordBuffer)
				{
					ExFreePoolWithTag(pThreadData->RecordBuffer, KANALYZER_POOL_TAG);
				}
				pThreadData->Start = 0;
				ExFreePoolWithTag(pThreadData, KANALYZER_POOL_TAG);
				*(ULONG_PTR *)((PUCHAR)pThread + THREAD_DATA_OFFSET) = NULL;

				InterlockedIncrement((LONG *)&g_threadExitCount);
			}
		}
	}
}

NTSTATUS SetKiTrapFaultHandler(void *context)
{
	const auto processorData =
		reinterpret_cast<PROCESSOR_DATA *>(ExAllocatePoolWithTag(
			NonPagedPool, sizeof(PROCESSOR_DATA), KANALYZER_POOL_TAG));
	if (!processorData) {
		__debugbreak();
	}
	RtlZeroMemory(processorData, sizeof(PROCESSOR_DATA));
	g_processorList[KeGetCurrentProcessorNumberEx(nullptr)] = processorData;

	//Initialize the disassembly engine
	ud_init(&processorData->UdObj);
	ud_set_mode(&processorData->UdObj, 32);
	ud_set_vendor(&processorData->UdObj, UD_VENDOR_INTEL); //intel
	ud_set_syntax(&processorData->UdObj, UD_SYN_INTEL);

	//Disable SMEP
	AsmStopSMEP();
	//Limit

	//KiTrapPageFault hook 
	IDTR idtr = {};
	__sidt(&idtr);
	PIDTENTRY idt_base = (PIDTENTRY)idtr.base;
	IDTENTRY  idt_entry = { 0 };
	memcpy(&idt_entry, &idt_base[14], sizeof(IDTENTRY));
	g_kitrap0e = (idt_entry.HiOffset << 16) | idt_entry.LowOffset;
	idt_entry.LowOffset = (unsigned short)((ULONG)KiTrapPageFault & 0xffff);
	idt_entry.HiOffset = (unsigned short)((ULONG)KiTrapPageFault >> 16);
	memcpy(&idt_base[14], &idt_entry, sizeof(IDTENTRY));

	return STATUS_SUCCESS;
}

NTSTATUS ResetKiTrapFaultHandler(void *context)
{
	PROCESSOR_DATA *processorData = g_processorList[KeGetCurrentProcessorNumber()];
	ExFreePoolWithTag(processorData, KANALYZER_POOL_TAG);

	IDTR idtr = {};
	__sidt(&idtr);
	PIDTENTRY idt_base = (PIDTENTRY)idtr.base;
	IDTENTRY  idt_entry = { 0 };
	memcpy(&idt_entry, &idt_base[14], sizeof(IDTENTRY));
	idt_entry.LowOffset = (unsigned short)((ULONG)g_kitrap0e & 0xffff);
	idt_entry.HiOffset = (unsigned short)((ULONG)g_kitrap0e >> 16);
	memcpy(&idt_base[14], &idt_entry, sizeof(IDTENTRY));
	return STATUS_SUCCESS;
}


ULONG __fastcall MyMiAllocateWsle(ULONG a1, ULONG pte, ULONG a3, ULONG a4,
	ULONG a5, ULONG pfn_l, ULONG pfn_h)
{
	bool    is_target = false;
	ULONG64 oldPa;

	if ((g_target_cr3 == __readcr3()) && g_target_active)
	{
		is_target = true;
		oldPa = *(ULONG64 *)pte;
	}

	ULONG ws_index = ((PfnMiAllocateWsle)g_TrampoMiAllocateWsle)(a1, pte, a3, a4, a5, pfn_l, pfn_h);

	if (is_target && ws_index && (pte < 0xC0400000))
	{
		ULONG64      pa = *(ULONG64 *)pte;
		ULONG        lva = (pte - 0xC0000000) << 9;
		ULONG        vfn = lva >> 12;
		THREAD_DATA *pThreadData = GET_THREAD_DATA();
		if (pThreadData)
		{	
			//DEBUG
			if (lva == (0x66000 + g_ntdll_base))
			{
				DbgPrint("ntdll!RtlBackoff. tid %d, pte %x, va %08x, pa %016llx\n", pThreadData->Tid, pte, lva, pa);
			}
			if (lva == (pThreadData->Teb + PAGE_SIZE)) //Extended teb 
			{
				DbgPrint("[MyMiAllocateWsle] ignore extended teb. pte %x, va %08x, pa %016llx\n", pte, lva, pa);
				return ws_index;
			}
			
			if (*(UCHAR *)((ULONG *)&g_pageState[lva >> 12] + 1) == 1)
			{
				//DbgPrint("[MyMiAllocateWsle] reserved. pThreadData %x, pte %x, va %08x, pa %016llx\n", pThreadData, pte, lva, pa);
				return ws_index;
			}
			if (g_stateTable[lva >> 12] == (PVOID)ANALYSIS_STATE_INIT_VALUE)
			{
				PVOID allocVa = AllocateFromUserSpaceBufferEntries(lva);
				g_stateTable[lva >> 12] = (PVOID)((ULONG)allocVa - lva);
				//DbgPrint("MyMiAllocateWsle. va %x, pa %llx, alloc_va %x\n", lva, pa, allocVa);
			}

			if (!(pa >> 63)) //nx = 0
			{
				ModifyExecutablePageEntry(pte, lva, pa);
			}
		}
		else
		{
			//DbgPrint("MyMiAllocateWsle attach. ethread %x, va %x, pa %llx\n", PsGetCurrentThread(), lva, pa);
		}
	}
	return ws_index;
}

int __fastcall MyMiCopyOnWriteEx(ULONG_PTR uva, ULONG pte, ULONG a3, ULONG a4, ULONG a5)
{
	ULONG64 oldPa = *(ULONG64 *)pte;
	int result = ((PfnMiCopyOnWriteEx)g_TrampoMiCopyOnWriteEx)(uva, pte, a3, a4, a5);
	if (result && (g_target_cr3 == __readcr3()) && g_target_active && (pte < 0xC0400000))
	{
		ULONG64 pa = *(ULONG64 *)pte;
		ULONG   lva = (pte - 0xC0000000) << 9;
		ULONG   vfn = lva >> 12;
		THREAD_DATA *pThreadData = GET_THREAD_DATA();
		if (pThreadData)
		{
			/*DbgPrint("MyMiCopyOnWriteEx. va %08x, pa %016llx, org %016llx\n", lva, pa, oldPa);*/
			if (*(UCHAR *)((ULONG *)&g_pageState[lva >> 12] + 1) == 1)
			{
				//DbgPrint("[MyMiCopyOnWriteEx] reserved. va %08x, pa %016llx, org %016llx\n", lva, pa, oldPa);
				return result;
			}

			if (g_stateTable[lva >> 12] == (PVOID)ANALYSIS_STATE_INIT_VALUE)
			{
				PVOID alloc_va = AllocateFromUserSpaceBufferEntries(lva);
				g_stateTable[lva >> 12] = (PVOID)((ULONG)alloc_va - lva);
			}

			if (!(pa >> 63)) //nx = 0
			{
				ModifyExecutablePageEntry(pte, lva, pa);
			}
		}
		else
		{
			//DbgPrint("MyMiCopyOnWriteEx attach. ethread %x, va %x, pa %llx\n", PsGetCurrentThread(), lva, pa);
		}
	}
	return result;
}

int __fastcall MyMiSetProtectionOnSection(ULONG eproc, ULONG vad, ULONG start_va, ULONG end_va,
	ULONG new_prot, ULONG out_old_prot, ULONG charge, ULONG locked)
{
	ULONG is_target = 0;
	if ((g_target_cr3 == __readcr3()) && g_target_active && (start_va < KERNEL_SPACE_BASE_ADDR))
	{
		is_target = 1;
		for (ULONG va = start_va; va <= end_va; va += 0x1000)
		{
			ULONG   vfn = va >> 12;
			ULONG   pte = 0xC0000000 + (va >> 9);	
			//Resotre
			PVOID  codePage = g_codeTable[vfn];
			if (((ULONG)codePage & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
			{	
				ULONG64 pa = *(ULONG64 *)pte;
				ULONG64 oldPa = pa;
				UCHAR   wr = *((UCHAR *)&g_pageState[vfn] + 2);
				UCHAR   nx = *((UCHAR *)&g_pageState[vfn] + 3);
				pa = (pa & 0x7FFFFFFFFFFFFFFF) | (ULONG64)(nx << 63);
				if (!(pa & 2ULL))  
				{
					pa = (pa & 0xFFFFFFFFFFFFFFFD) | (ULONG64)(wr << 1);
				}
				*(ULONG64 *)pte = pa;	
				__invlpg((PVOID)va);

				DbgPrint("[MiSetProtectionOnSection] restore, va %08x, pa %llx -> %016llx, write %x\n",
					va, oldPa, pa, wr);
			}
		}
	}

	int status = ((PfnMyMiSetProtectionOnSection)g_TrampoMiSetProtectionOnSection)(eproc,
		vad, start_va, end_va, new_prot, out_old_prot, charge, locked);

	if (is_target && NT_SUCCESS(status))
	{
		if (new_prot & 0xF0)  //EXECUTE
		{
			for (ULONG va = start_va; va <= end_va; va += 0x1000)
			{
				ULONG   vfn = va >> 12;
				ULONG   pte = 0xC0000000 + (va >> 9);			

				PVOID   codePage = g_codeTable[vfn];
				if (((ULONG)codePage & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
				{
					ULONG64 pa = *(ULONG64 *)pte;
					ULONG64 oldPa = pa;
					*(UCHAR *)((UCHAR *)&g_pageState[vfn] + 2) = (UCHAR)((pa >> 1) & 1);
					*(UCHAR *)((UCHAR *)&g_pageState[vfn] + 3) = 0;

					pa = (pa | (1LL << 63)) & (~2LL); //XD = 1, W = 0
					*(ULONG64 *)pte = pa;
					__invlpg((PVOID)va);

					DbgPrint("[MiSetProtectionOnSection] execute. va %08x, pa %llx -> %016llx, prot %x -> %x.\n",
						va, oldPa, pa, out_old_prot, new_prot);
				}
			}
		}
	}
	return status;
}

void __fastcall MyMiDeleteVirtualAddresses(ULONG start_va, ULONG end_va, ULONG a3, ULONG a4, ULONG a5)
{
	if ((g_target_cr3 == __readcr3()) && (start_va < KERNEL_SPACE_BASE_ADDR))
	{
		for (ULONG va = start_va; va <= end_va; va += 0x1000)
		{
			ULONG   pte = 0xC0000000 + (va >> 9);
			ULONG   vfn = va >> 12;		
			if (g_target_active)
			{
				DeallocateUserSpaceBufferEntries(vfn);
			}
		}
	}
	((PfnMiDeleteVirtualAddresses)g_TrampoMiDeleteVirtualAddresses)(start_va, end_va, a3, a4, a5);
}

NTSTATUS __stdcall MyNtReadFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
)
{
	NTSTATUS status;

	InterlockedIncrement((LONG *)&gNtReadFileCount);

	if (g_target_pid != PsGetCurrentProcessId())
	{
		InterlockedDecrement((LONG *)&gNtReadFileCount);
		return origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
			Buffer, Length, ByteOffset, Key);
	}
	status = origNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
		Buffer, Length, ByteOffset, Key);
	if (status == STATUS_SUCCESS)
	{
		PFILE_OBJECT pFileObj;
		ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
			KernelMode, (PVOID *)&pFileObj, NULL);
		POBJECT_NAME_INFORMATION pFullPath;
		ULONG uRealSize;
		pFullPath = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 1024);
		ObQueryNameString(pFileObj, pFullPath, 1024, &uRealSize);
		ObDereferenceObject(pFileObj);
		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress((PVOID)Buffer);

		/*if (wcsstr(pFullPath->Name.Buffer, L"input.txt"))
		{
			if (g_read_bytes)
			{
				ULONG realReadLen = IoStatusBlock->Information;
				ULONG taintLen = g_read_bytes;
				if (g_read_bytes > realReadLen)
				{
					taintLen = realReadLen;
				}
				g_read_bytes -= taintLen;

				for (ULONG i = 0; i < taintLen; i++)
				{
					UINT32   va = (ULONG)Buffer + i;
					UINT32   mapVa = (UINT32)g_stateTable[va >> 12] + va;
					*(UINT8 *)mapVa = 1;
				}
				g_taint_set = 1;
				DbgPrint("<TAINT_SOURCE> realReadLen %u, taintLen %u.\n", realReadLen, taintLen);
			}
		}*/

		ExFreePool(pFullPath);
	}

	InterlockedDecrement((LONG *)&gNtReadFileCount);
	return status;
}

NTSTATUS __stdcall MyNtWriteFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key)
{
	HANDLE   pid = PsGetCurrentProcessId();

	InterlockedIncrement((LONG *)&gNtWriteFileCount);

	if (pid == g_target_pid)
	{
		PFILE_OBJECT pFileObj;
		ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
			KernelMode, (PVOID *)&pFileObj, NULL);
		POBJECT_NAME_INFORMATION pFullPath;
		ULONG uRealSize;
		pFullPath = (POBJECT_NAME_INFORMATION)ExAllocatePool(NonPagedPool, 1024);
		ObQueryNameString(pFileObj, pFullPath, 1024, &uRealSize);
		ObDereferenceObject(pFileObj);

		PHYSICAL_ADDRESS lpa = MmGetPhysicalAddress((PVOID)Buffer);

		//if (!wcsstr(pFullPath->Name.Buffer, L"ConDrv"))
		//{
		//	 DbgPrint("<NtWriteFile> tid %d, time %u, file %wZ, buffer %x, pa %llx, length %d.\n",
		//		 PsGetCurrentThreadId(), QueryTimeMillisecond(), &pFullPath->Name,
		//		 Buffer, lpa.QuadPart, Length);
		//}	

		/*if (wcsstr(pFullPath->Name.Buffer, L"Output.7z"))
		{
			if ((g_write_count++) < 8)
			{
				ULONG tsCount = 0;
				for (ULONG i = 0; i < Length; i++)
				{
					UINT32  va = (ULONG)Buffer + i;
					UINT32  mapVa = (UINT32)g_stateTable[va >> 12] + va;
					if (*(UINT8 *)(mapVa + i))
					{
						tsCount++;
					}
				}
				DbgPrint("<TAINT_SINK> Buffer %x, length %u, check count %d.\n", Buffer, Length, tsCount);
			}
		}*/

		ExFreePool(pFullPath);
	}
	NTSTATUS status = origNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
		Length, ByteOffset, Key);

	InterlockedDecrement((LONG *)&gNtWriteFileCount);

	return status;
}

NTSTATUS __stdcall MyNtDeviceIoControlFile(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG            IoControlCode,
	PVOID            InputBuffer,
	ULONG            InputBufferLength,
	PVOID            OutputBuffer,
	ULONG            OutputBufferLength)
{
	NTSTATUS status;
	HANDLE pid = PsGetCurrentProcessId();

	InterlockedIncrement((LONG *)&gNtDeviceIoCount);

	if (pid == g_target_pid)
	{
		THREAD_DATA *pThreadData = GET_THREAD_DATA();
		if (IoControlCode == 0x1201f) //IOCTL_AFD_SEND
		{
			PAFD_INFO pAfdInfo = (PAFD_INFO)InputBuffer;

			//DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, handle %x, send buf %x, len %u\n",
			//	PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, 
			//	pAfdInfo->BufferArray->buf, pAfdInfo->BufferArray->len);
		}
		else if (IoControlCode == 0x12017) //IOCTL_AFD_RECV
		{
			status = origNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
				IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
			PAFD_INFO pAfdInfo = (PAFD_INFO)InputBuffer;
			if (status == STATUS_SUCCESS)
			{
				PVOID recvBuf = pAfdInfo->BufferArray->buf;
				ULONG recvLen = IoStatusBlock->Information;

				//DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, handle %x, sync recv, buf %x, len %d, input len %d\n",
				//	PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, recvBuf, recvLen, pAfdInfo->BufferArray->len);

			}
			else if (status == STATUS_PENDING)
			{
				PFILE_OBJECT pFileObj;
				ObReferenceObjectByHandle(FileHandle, GENERIC_READ, *IoFileObjectType,
					KernelMode, (PVOID *)&pFileObj, NULL);

				pThreadData->RecvPending = 1;

				//DbgPrint("<NtDeviceIoControlFile> tid %d, time %u, handle %x, pending recv, buf %x, ApcRoutine %x, FileObj %x\n",
				//	PsGetCurrentThreadId(), QueryTimeMillisecond(), FileHandle, pAfdInfo->BufferArray->buf, ApcRoutine, pFileObj);

				ObDereferenceObject(pFileObj);
			}
			InterlockedDecrement((LONG *)&gNtDeviceIoCount);
			return status;
		}
	}
	status = origNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext,
		IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength,
		OutputBuffer, OutputBufferLength);

	InterlockedDecrement((LONG *)&gNtDeviceIoCount);

	return status;
}

VOID WPOFF()
{
	ULONG_PTR cr0 = 0;
	cr0 = __readcr0();
	cr0 &= ~0x10000ull;
	__writecr0(cr0);
}

VOID WPON()
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
}

VOID WriteJumpKernel(VOID *pAddress, ULONG_PTR JumpTo)
{
	UCHAR *pCur = (UCHAR *)pAddress;
#ifdef _M_IX86

	*pCur = 0xff;     // jmp [addr]
	*(++pCur) = 0x25;
	pCur++;
	*((ULONG *)pCur) = (ULONG)(((ULONG_PTR)pCur) + sizeof(ULONG));
	pCur += sizeof(ULONG);
	*((ULONG_PTR *)pCur) = JumpTo;

#else ifdef _M_AMD64

	*pCur = 0xff;		// jmp [rip+addr]
	*(++pCur) = 0x25;
	*((ULONG *) ++pCur) = 0; // addr = 0
	pCur += sizeof(ULONG);
	*((ULONG_PTR *)pCur) = JumpTo;

#endif
}

PVOID InlineHookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, ULONG InsSize)
{
	UCHAR *pBridgeBuffer = (UCHAR *)ExAllocatePoolWithTag(NonPagedPool, 32, 'KanL');
	if (pBridgeBuffer == NULL)
	{
		DbgPrint("InlineHookFunction ExAllocatePoolWithTag error\n");
		return NULL;
	}
	memcpy(pBridgeBuffer, (VOID *)OriginalFunction, InsSize);
	//jmp OrigFunc + InstrSize
	WriteJumpKernel(&pBridgeBuffer[InsSize], OriginalFunction + InsSize);
	WriteJumpKernel((VOID *)OriginalFunction, NewFunction);

	return pBridgeBuffer;
}

VOID InlineUnHookFunction(ULONG_PTR OriginalFunction, ULONG_PTR BridgeBuffer, ULONG InsSize)
{
	memcpy((VOID *)OriginalFunction, (VOID *)BridgeBuffer, InsSize);
	ExFreePoolWithTag((PVOID)BridgeBuffer, 'KanL');
}

LONG64 InlineHookSpecial(ULONG_PTR OriginAddr, ULONG_PTR NewAddr)
{
	unsigned char jmpBuf[8] = {0xe9, 0, 0, 0, 0, 0x90, 0x90, 0x90};
	*(ULONG *)((unsigned char *)jmpBuf + 1) = NewAddr - OriginAddr - 5;
	LONG64 originBytes = InterlockedExchange64((LONG64 *)OriginAddr, *(LONG64 *)jmpBuf);

	return originBytes;
}

VOID InlineUnHookSpecial(ULONG_PTR OriginAddr, LONG64 OriginBytes)
{
	InterlockedExchange64((LONG64 *)OriginAddr, OriginBytes);
}

void Hook()
{
	WPOFF();

	//Syscall
	/*origNtReadFile = (PfnNtReadFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwReadFile),
		(LONG)MyNtReadFile);
	origNtDeviceIoControlFile = (PfnNtDeviceIoControlFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwDeviceIoControlFile),
		(LONG)MyNtDeviceIoControlFile);
	origNtWriteFile = (PfnNtWriteFile)InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwWriteFile),
		(LONG)MyNtWriteFile);*/

	//Inline
	g_TrampoMiAllocateWsle = InlineHookFunction(g_MiAllocateWsle, (ULONG_PTR)MyMiAllocateWsle, 11);
	g_TrampoMiCopyOnWriteEx = InlineHookFunction(g_MiCopyOnWriteEx, (ULONG_PTR)MyMiCopyOnWriteEx, 14);
	g_TrampoMiDeleteVirtualAddresses = InlineHookFunction(g_MiDeleteVirtualAddresses, (ULONG_PTR)MyMiDeleteVirtualAddresses, 14);
	g_TrampoMiSetProtectionOnSection = InlineHookFunction(g_MiSetProtectionOnSection, (ULONG_PTR)MyMiSetProtectionOnSection, 14);
	//Teb
	g_TrampoMmCreateTeb = InlineHookFunction(g_MmCreateTeb, (ULONG_PTR)MyMmCreateTeb, 11);
	//Context
	g_SwapContextBytes = InlineHookSpecial(g_SwapContext, (ULONG_PTR)MySwapContext);	
	//Service
	g_TrampoKiFastCallEntry = InlineHookFunction(g_KiFastCallEntry, (ULONG_PTR)KiFastCallEntry, 10);
	g_TrampoKiServiceExit = InlineHookFunction(g_KiServiceExit, (ULONG_PTR)KiServiceExit, 10);
	g_TrampoKei386HelperExit = InlineHookFunction(g_Kei386HelperExit, (ULONG_PTR)Kei386HelperExit, 10);
	g_TrampoKiCallUserModeExit = InlineHookFunction(g_KiCallUserModeExit, (ULONG_PTR)KiCallUserModeExit, 10);

	WPON();
}

void Unhook()
{
	WPOFF();
	if (g_TrampoMmAccessFault)
	{
		InlineUnHookFunction(g_MmAccessFault, (ULONG_PTR)g_TrampoMmAccessFault, 11);
	}
	if (g_TrampoMiAllocateWsle)
	{
		InlineUnHookFunction(g_MiAllocateWsle, (ULONG_PTR)g_TrampoMiAllocateWsle, 11);
	}
	if (g_TrampoMiCopyOnWriteEx)
	{
		InlineUnHookFunction(g_MiCopyOnWriteEx, (ULONG_PTR)g_TrampoMiCopyOnWriteEx, 14);
	}
	if (g_TrampoMiDeleteVirtualAddresses)
	{
		InlineUnHookFunction(g_MiDeleteVirtualAddresses, (ULONG_PTR)g_TrampoMiDeleteVirtualAddresses, 14);
	}
	if (g_TrampoMiSetProtectionOnSection)
	{
		InlineUnHookFunction(g_MiSetProtectionOnSection, (ULONG_PTR)g_TrampoMiSetProtectionOnSection, 14);
	}
	//TEB
	if (g_TrampoMmCreateTeb)
	{ 
		InlineUnHookFunction(g_MmCreateTeb, (ULONG_PTR)g_TrampoMmCreateTeb, 11);
	}
	if (g_TrampoIopfCompleteRequest)
	{
		InlineUnHookFunction(g_IopfCompleteRequest, (ULONG_PTR)g_TrampoIopfCompleteRequest, 10);
	}
	//Context
	if (g_SwapContextBytes)
	{
		InlineUnHookSpecial(g_SwapContext, g_SwapContextBytes);
	}
	if (g_TrampoKiFastCallEntry)
	{
		InlineUnHookFunction(g_KiFastCallEntry, (ULONG_PTR)g_TrampoKiFastCallEntry, 10);
	}
	if (g_TrampoKiServiceExit)
	{
		InlineUnHookFunction(g_KiServiceExit, (ULONG_PTR)g_TrampoKiServiceExit, 10);
	}
	if (g_TrampoKei386HelperExit)
	{
		InlineUnHookFunction(g_Kei386HelperExit, (ULONG_PTR)g_TrampoKei386HelperExit, 10);
	}
	if (g_TrampoKiCallUserModeExit)
	{
		InlineUnHookFunction(g_KiCallUserModeExit, (ULONG_PTR)g_TrampoKiCallUserModeExit, 10);
	}

	//syscall
	/*InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwReadFile), (LONG)origNtReadFile);
	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwDeviceIoControlFile), (LONG)origNtDeviceIoControlFile);
	InterlockedExchange((PLONG)&SYSTEMSERVICE(SYSCALL_ZwWriteFile), (LONG)origNtWriteFile);*/

	WPON();
}

void DriverUnload(PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);
	PAGED_CODE();

	DbgPrint("\n[kanalyzer] Driver unload.\n");

	//Clear
	g_target_active = false;
	g_target_cr3 = 0;
	g_target_pid = (HANDLE)-1;
	g_target_eprocess = NULL;

	DbgPrint("[kanalyzer] Wait...\n");
	while (gNtReadFileCount || gNtWriteFileCount || gNtDeviceIoCount)
	{
		LARGE_INTEGER my_interval;
		my_interval.QuadPart = (-10 * 1000); //1ms
		KeDelayExecutionThread(KernelMode, 0, &my_interval);
	}

	if (g_kitrap0e)
	{
		ExecuteOnAllProcessors(ResetKiTrapFaultHandler, NULL);
	}

	if (g_pageState)
	{
		ExFreePoolWithTag(g_pageState, KANALYZER_POOL_TAG);
	}

	Unhook();

	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
	PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutineEx);
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyCallback);

	UNICODE_STRING  ntWin32NameString;
	RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&ntWin32NameString);
	if (driver_object->DeviceObject)
		IoDeleteDevice(driver_object->DeviceObject);

	DbgPrint("\n--------------------------- [kanalyzer] --------------------------\n\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(registry_path);
	PAGED_CODE();

	NTSTATUS  status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING  ntUnicodeString;
	UNICODE_STRING  ntWin32NameString;
	PDEVICE_OBJECT  deviceObject = NULL;
	RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);
	status = IoCreateDevice(driver_object, 0, &ntUnicodeString, FILE_DEVICE_UNKNOWN,   
		FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);  
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[kanalyzer] Couldn't create the device object\n");
		return status;
	}
	RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&ntWin32NameString, &ntUnicodeString);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[kanalyzer] Couldn't create symbolic link\n");
		IoDeleteDevice(deviceObject);
	}
	driver_object->MajorFunction[IRP_MJ_CREATE] = IoctlCreateClose;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = IoctlCreateClose;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDeviceControl;
	driver_object->DriverUnload = DriverUnload;

	g_pDeviceObj = deviceObject;

	//DEBUG
	__debugbreak();

	DbgPrint("\n+++++++++++++++++++++++++ [kanalyzer] ++++++++++++++++++++++++++\n\n");

	LDR_DATA_TABLE_ENTRY *pLdrTable = NULL;
	pLdrTable = (LDR_DATA_TABLE_ENTRY*)driver_object->DriverSection;
	PLIST_ENTRY pModuleEntry = pLdrTable->InLoadOrderLinks.Flink;
	while (pModuleEntry != &pLdrTable->InLoadOrderLinks)
	{
		LDR_DATA_TABLE_ENTRY *pCurModule = (LDR_DATA_TABLE_ENTRY *)pModuleEntry;
		if (wcsstr(pCurModule->BaseDllName.Buffer, L"ntoskrnl"))
		{
			//memory
			g_MmAccessFault = (ULONG)pCurModule->DllBase + OFFSET_MmAccessFault;
			g_MiAllocateWsle = (ULONG)pCurModule->DllBase + OFFSET_MiAllocateWsle;
			g_MiCopyOnWriteEx = (ULONG)pCurModule->DllBase + OFFSET_MiCopyOnWriteEx;
			g_MiDeletePteRun = (ULONG)pCurModule->DllBase + OFFSET_MiDeletePteRun;
			g_MiDeleteVirtualAddresses = (ULONG)pCurModule->DllBase + OFFSET_MiDeleteVirtualAddresses;
			g_MiSetProtectionOnSection = (ULONG)pCurModule->DllBase + OFFSET_MiSetProtectionOnSection;
			pZwProtectVirtualMemory = (PfnZwProtectVirtualMemory)((ULONG)pCurModule->DllBase + OFFSET_ZwProtectVirtualMemory);
			pZwWriteVirtualMemory = (PfnZwWriteVirtualMemory)((ULONG)pCurModule->DllBase + OFFSET_ZwWriteVirtualMemory);
			pZwQueryVirtualMemory = (PfnZwQueryVirtualMemory)((ULONG)pCurModule->DllBase + OFFSET_ZwQueryVirtualMemory);
			g_MmPfnDatabase = *(ULONG *)((ULONG)pCurModule->DllBase + OFFSET_MmPfnDatabase);
			//teb
			g_MmCreateTeb = (ULONG)pCurModule->DllBase + OFFSET_MmCreateTeb;
			g_MmCreateTebBack = (ULONG)pCurModule->DllBase + OFFSET_MmCreateTebBack;
			g_PspAllocateThread = (ULONG)pCurModule->DllBase + OFFSET_PspAllocateThread;
			g_PspAllocateThreadBack = (ULONG)pCurModule->DllBase + OFFSET_PspAllocateThreadBack;
			//io
			g_IopfCompleteRequest = (ULONG)pCurModule->DllBase + OFFSET_IopfCompleteReq;
			//context
			g_SwapContext = (ULONG)pCurModule->DllBase + OFFSET_SwapContext;
			g_SwapContextBack = (ULONG)pCurModule->DllBase + OFFSET_SwapContextBack;
			//sysexit
			g_KiFastCallEntry = (ULONG)pCurModule->DllBase + OFFSET_KiFastCallEntry;
			g_KiServiceExit = (ULONG)pCurModule->DllBase + OFFSET_KiServiceExit;
			g_Kei386HelperExit = (ULONG)pCurModule->DllBase + OFFSET_Kei386HelperExit;
			g_KiCallUserModeExit = (ULONG)pCurModule->DllBase + OFFSET_KiCallUserModeExit;
			//Apc
			KeInitializeApc = (PfnKeInitializeApc)((ULONG)pCurModule->DllBase + OFFSET_KeInitializeApc);
			KeInsertQueueApc = (PfnKeInsertQueueApc)((ULONG)pCurModule->DllBase + OFFSET_KeInsertQueueApc);
		}
		pModuleEntry = pModuleEntry->Flink;
	}
	KeInitializeGuardedMutex(&g_allocMutex);

	//Not optimized£¬~ g_codeTable
	g_pageState = (ULONG64 *)ExAllocatePoolWithTag(NonPagedPool, 0x80000 * 8, KANALYZER_POOL_TAG);
	if (!g_pageState)
	{
		DbgPrint("Allocate g_pageState error.\n");
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(g_pageState, 0x80000 * 8);
	
	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)ProcessNotifyRoutineEx, FALSE);
	status = PsSetCreateThreadNotifyRoutineEx(PsCreateThreadNotifyNonSystem, CreateThreadNotifyRoutineEx);
	status = PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback);

	Hook();
	ExecuteOnAllProcessors(SetKiTrapFaultHandler, NULL);

	RTL_OSVERSIONINFOW verInfo;
	RtlGetVersion(&verInfo);

	DbgPrint("[kanalyzer] Driver entry, system version %u %u %u\n", 
		verInfo.dwMajorVersion, verInfo.dwMinorVersion, verInfo.dwBuildNumber);

	return status;
}


} //extern "c"
