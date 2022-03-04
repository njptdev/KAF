#pragma once

#include "udis86.h"

extern "C" {


#define   KANALYZER_POOL_TAG     'KANZ'

#define   NT_DEVICE_NAME      L"\\Device\\KernelAnalyzerDevice"
#define   DOS_DEVICE_NAME     L"\\DosDevices\\KernelAnalyzerIoctl"

#define IOCTL_KANALYZER_THREAD_START  CTL_CODE(FILE_DEVICE_UNKNOWN, 0X950, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Windows 10 (1503) 32-bit, change according to the system version
#define PD_EPROCESS_OFFSET                  0x18
#define PID_ETHREAD_OFFSET                  0x374
#define THREAD_DATA_OFFSET                  0x440   //ETHREAD +440h UserGsBase;
#define TEB_OFFSET                          0xa8
#define NTDLL_APC_DISPATCHER_OFFSET         0x845d0
#define NTDLL_EXCEPTION_DISPATCHER_OFFSET	0x84690 
#define NTDLL_CALLBACK_DISPATCHER_OFFSET	0x84640
#define USER32_CLIENT_THREAD_OFFSET         0x6BC0
#define OFFSET_NTDLL_WAIT_ON_ADDRESS        0x54470 //RtlWaitOnAddress
//inline
#define	OFFSET_MmAccessFault            0xC8AD0
#define	OFFSET_MiAllocateWsle           0xD2790
#define	OFFSET_MiCopyOnWriteEx          0x5C120
#define	OFFSET_MiDeletePteRun           0xCB850
#define	OFFSET_MiDeleteVirtualAddresses 0xD3CD0
#define	OFFSET_MiSetProtectionOnSection 0xCE960
#define	OFFSET_ZwProtectVirtualMemory  0x124B10
#define	OFFSET_ZwWriteVirtualMemory    0x123BC0
#define	OFFSET_ZwQueryVirtualMemory	   0x124700 //Zw £¬ Nt:0x38018E
#define	OFFSET_MmPfnDatabase           0x27132C
//teb
#define	OFFSET_MmCreateTeb             0x2D67FE
#define	OFFSET_MmCreateTebBack         0x2D6809
#define	OFFSET_PspAllocateThread       0x400EBE
#define	OFFSET_PspAllocateThreadBack   0x400EC8
#define	OFFSET_SwapContext             0x1390F6
#define	OFFSET_SwapContextBack         0x139100
//io
#define OFFSET_IopfCompleteReq         0x54D10
//service
#define	OFFSET_KiFastCallEntry         0x134A61
#define	OFFSET_KiServiceExit           0x134CD4
#define	OFFSET_Kei386HelperExit        0x135839
#define	OFFSET_KiCallUserModeExit      0x12619D
//apc
#define	OFFSET_KeInitializeApc         0x2D010
#define	OFFSET_KeInsertQueueApc        0x7A454
//sycall
#define SYSCALL_ZwReadFile                0x8c
#define SYSCALL_ZwWriteFile               0x7
#define SYSCALL_ZwDeviceIoControlFile     0x13c


#define   KERNEL_SPACE_BASE_ADDR        0x80000000
#define   MAX_ALLOCATE_NUMBER           8

//Can be moved to the extended space
#define   TEB_PROFILER_OFFSET           0x50
//0x60 ~ 0x80, 0x100 ~ 0x120, save context
#define   TEB_LOG_BUFFER_OFFSET         0x80
#define   TEB_LOCAL_BUFFER_BASE_OFFSET  0x84
#define   TEB_AUX_PAGE_BASE_OFFSET      0x88

#define   REG_STATE_SLOT_OFFSET         0x120    //PAGE_SIZE
//Extended
#define   TEB_COUNTER_SLOT_OFFSET       PAGE_SIZE + 0x30
#define   TEB_RECORD_SLOT_OFFSET        PAGE_SIZE + 0x60

#define   GET_THREAD_DATA()   \
	(THREAD_DATA *)*(ULONG_PTR *)((PUCHAR)PsGetCurrentThread() + THREAD_DATA_OFFSET)

//Analysis
#define   PARSE_BLOCK_SEQ_NUM           1 

/* 
At present, buffer allocation is not dynamically managed and can be adjusted based on actual conditions. 
If the memory overhead is too high, physical pages may be swapped out of the memory.
Try to reload the driver for each test or reboot the target system.
*/
#define   CODE_TABLE_SIZE         0x80000 * 4    //2MB
#define   BUFFER_ENTRY_SIZE       8*1024*1024    //8MB

#define   CACHE_CODE_MAP_SIZE     32*1024*1024   //32MB

#define   CACHE_MEM_STATE_NUM     2              
#define   CACHE_MEM_STATE_SIZE    64*1024*1024   //64MB*2

#define   PER_CPU_ALLOCATE_SIZE   48*1024*1024   //48MB£¬rewriting
#define   PER_CPU_CODE_BUF_SIZE   32*1024*1024   //32MB
#define   PER_CPU_HEAD_BUF_SIZE   15*1024*1024   //15MB
#define   PER_CPU_TEMP_BUF_SIZE    1*1024*1024   //1MB


//SPEC CPU2017
//#define   CODE_TABLE_SIZE         0x80000 * 4    
//#define   BUFFER_ENTRY_SIZE       8*1024*1024    
//
//#define   CACHE_CODE_MAP_SIZE     40*1024*1024   
//
//#define   CACHE_MEM_STATE_NUM     8              
//#define   CACHE_MEM_STATE_SIZE    64*1024*1024   
//
//#define   PER_CPU_ALLOCATE_SIZE   30*1024*1024   
//#define   PER_CPU_CODE_BUF_SIZE   24*1024*1024   
//#define   PER_CPU_HEAD_BUF_SIZE    5*1024*1024   
//#define   PER_CPU_TEMP_BUF_SIZE    1*1024*1024  

//deepsjeng_r
//#define   CODE_TABLE_SIZE         0x80000 * 4
//#define   BUFFER_ENTRY_SIZE       6*1024*1024
//
//#define   CACHE_CODE_MAP_SIZE     8*1024*1024 
//
//#define   CACHE_MEM_STATE_NUM     6
//#define   CACHE_MEM_STATE_SIZE    64*1024*1024
//
//#define   PER_CPU_ALLOCATE_SIZE    9*1024*1024  
//#define   PER_CPU_CODE_BUF_SIZE    6*1024*1024  
//#define   PER_CPU_HEAD_BUF_SIZE    2*1024*1024   
//#define   PER_CPU_TEMP_BUF_SIZE    1*1024*1024 


typedef struct _PROCESSOR_DATA {
	ULONG_PTR      Kitrap01;
	ULONG_PTR      Kitrap0e;
	//Buffer
	PMDL           BufMdl;
	ULONG          BufBase;
	ULONG          BufPtr;
	ULONG          HdBufBase;
	ULONG          HdBufPtr;
	ULONG          TmpBufBase;
	ULONG          TmpBufPtr;
	//Parse
	ULONG          DisIp;
	UCHAR          *CodePtr;
	ud_t           UdObj;
	//Counter
	ULONG64        Counter0;
	ULONG64        Counter1;
	ULONG64        Counter2;
	ULONG64        Counter3;
	ULONG64        Counter4;
	ULONG64        Counter5;
	ULONG64        Counter6;
	ULONG64        Counter7;
}PROCESSOR_DATA, *PPROCESSOR_DATA;


typedef struct _WRITE_WORK {
	PIO_WORKITEM WorkItem;
	KDPC         Dpc;
	PVOID        ThreadData;
	ULONG        Index;     //Buffer index
	ULONG        Param;     
} WRITE_WORK;

typedef struct _BUFFER_LIST {
	LIST_ENTRY  ListHead;
	KSPIN_LOCK  SpinLock;
	KSEMAPHORE  Semaphore;
	ULONG       Count;
}BUFFER_LIST, *PBUFFER_LIST;

typedef struct _BUFFER_ENTRY {
	LIST_ENTRY  ListEntry;
	PVOID       Ptr;
	PMDL        Mdl;
}BUFFER_ENTRY, *PBUFFER_ENTRY;

typedef struct _STATE_BUFFER_ENTRY {
	LIST_ENTRY        ListEntry;
	PVOID             Address;
}STATE_BUFFER_ENTRY, *PSTATE_BUFFER_ENTRY;

typedef struct _THREAD_DATA{
	ULONG        Pid;
	ULONG        Tid;
	ULONG        Teb;
	ULONG        Start;
	ULONG        Syscall;
	PMDL         TebExtendMdl;
	ULONG        RecvPending;
	KAPC         RecvApc;
	PVOID        RecordBuffer;
} THREAD_DATA, *PTHREAD_DATA;

typedef struct _KTRAP_FRAME3
{
	ULONG SegFs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG TempEFlags;
	ULONG Reserved;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KTRAP_FRAME3, *PKTRAP_FRAME3;

typedef NTSTATUS (NTAPI *PfnZwQueryVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
	_Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
	_In_ SIZE_T MemoryInformationLength,
	_Out_opt_ PSIZE_T ReturnLength
	);

void  MySwapContext();
void  MyMmCreateTeb();
void  MyPspAllocateThread();

void  KiTrapPageFault();
void  KiFastCallEntry();
void  KiServiceExit();
void  Kei386HelperExit();
void  KiCallUserModeExit();

ULONG __stdcall AsmEnableInterrupt();
ULONG __stdcall AsmDisableInterrupt();

VOID __stdcall AsmStopSMEP();

void __stdcall AsmUserWaitFunction();
void __stdcall AsmUserWaitFunctionEnd();
void __stdcall AsmAnalysisCheckStub();

void __stdcall AsmAnalysisSyscallTrap();
void __stdcall AsmFlushAllTlb();

void __stdcall AsmEnterIntoAnalysisCode(PVOID StartAddr, PVOID WorkBuffer, PVOID AuxBuffer, PVOID ThreadData);
void __stdcall AsmEnterIntoAnalysisCode2(PVOID StartAddr, PVOID WorkBuffer, PVOID LogPtr, PVOID ThreadData);

IO_WORKITEM_ROUTINE_EX WriteWorkitemRoutineEx;

}