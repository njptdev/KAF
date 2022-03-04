#ifndef KERNELPLATFORM_ANALYZER_H_
#define KERNELPLATFORM_ANALYZER_H_

#include <fltKernel.h>

extern "C" {

#define  LOG_SYSENTER_FLAG          0xEEEE
#define  LOG_ROLLBACK_FAULT_ADDR    0xFFFFAAAA
#define  ANALYSIS_CODE_FAULT_BASE   0xAAA00000

#define  ANALYSIS_STATE_INIT_VALUE  0x80000000



typedef struct _BLOCK_PROFILER
{
	ULONG  FaultIp;       
	ULONG  BranchOffset1;  //far
	ULONG  BranchOffset2;  //near£¬next
	USHORT Flag;           
	USHORT Syscall;
	ULONG  BlockSize;
	ULONG  BlockHash;
	ULONG  CodeBytesPtr;   
	ULONG  DynamicCodePtr;
	KSPIN_LOCK        Lock;
	SINGLE_LIST_ENTRY FromListHead;
}BLOCK_PROFILER, *PBLOCK_PROFILER;

typedef struct _FROM_NODE
{
	SINGLE_LIST_ENTRY ListEntry;
	PBLOCK_PROFILER   Profiler;
}FROM_NODE, *PFROM_NODE;

typedef struct _MMPTE_HARDWARE {
	ULONG64 Valid : 1;
	ULONG64 Writable : 1;        
	ULONG64 Owner : 1;            
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1; // software field
	ULONG64 Prototype : 1;   // software field
	ULONG64 Write : 1;       // software field - MP change
	ULONG64 PageFrameNumber : 26;
	ULONG64 reserved1 : 25;
	ULONG64 NoExecute : 1;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE_SOFTWARE {
	ULONG64 Valid : 1;
	ULONG64 PageFileLow : 4;
	ULONG64 Protection : 5;
	ULONG64 Prototype : 1;
	ULONG64 Transition : 1;
	ULONG64 PageFileReserved : 1;
	ULONG64 PageFileAllocated : 1;
	ULONG64 Unused : 18;
	ULONG64 PageFileHigh : 32;
} MMPTE_SOFTWARE, *PMMPTE_SOFTWARE;

typedef struct _U4_MMPFN {
	ULONG PteFrame : 24;     //containing page, 0:24
	ULONG AweAllocation : 1; //These pages are either noaccess, readonly or readwrite.
	ULONG Unknown1 : 1;
	ULONG Unknown2 : 1;
	ULONG PrototypePte : 1; 
	ULONG Unknown3 : 4;
}U4_MMPFN;

typedef struct _MMPFN {
	ULONG           WsIndex;     //u1
	PMMPTE_HARDWARE PteAddress;
	MMPTE_SOFTWARE  OriginalPte; 
	ULONG           ShareCount;  //u2
	USHORT          ReferenceCount;
	USHORT          e1;          //u3
	U4_MMPFN        u4;
} MMPFN, *PMMPFN;

typedef struct _KPAGE_FAULT_FRAME
{
	ULONG Edi;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG SegFs;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KPAGE_FAULT_FRAME, *PKPAGE_FAULT_FRAME;

typedef struct _KPAGE_FAULT_KERNEL_FRAME
{
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG SegFs;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
} KPAGE_FAULT_KERNEL_FRAME, *PKPAGE_FAULT_KERNEL_FRAME;

typedef struct _KTRAP_FRAME
{
	ULONG DbgEbp;
	ULONG DbgEip;
	ULONG DbgArgMark;
	//ULONG DbgArgPointer; //win 10
	USHORT TempSegCs;
	UCHAR Logging;
	UCHAR Reserved;
	ULONG TempEsp;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	ULONG SegGs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG PreviousPreviousMode;
	ULONG MxCsr; //win 10
	PEXCEPTION_REGISTRATION_RECORD ExceptionList;
	ULONG SegFs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Ebp;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
	ULONG V86Es;
	ULONG V86Ds;
	ULONG V86Fs;
	ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

typedef struct _KANALYSIS_FAULT_FRAME
{
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG SegFs;
	ULONG ErrCode;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG HardwareEsp;
	ULONG HardwareSegSs;
} KANALYSIS_FAULT_FRAME, *PKANALYSIS_FAULT_FRAME;

ULONG QueryTimeMillisecond();


}
#endif
