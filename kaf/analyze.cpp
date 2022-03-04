#include "analyze.h"
#include "driver.h"
#include "stdint.h"

#include <limits.h>
#include <intrin.h>


extern "C" {

extern PVOID           g_target_eprocess;
extern PROCESSOR_DATA *g_processorList[];

UCHAR cmovOpCode[] = { 0x47,0x43,0x42,0x46,0x4f,0x4d,0x4c,0x4e,
					  0x41,0x4b,0x49,0x45,0x40,0x4a,0x48,0x44 };
USHORT setccOpCode[] = { 0x0197,0x0193,0x0192,0x0196,0x019F,0x019d,0x019C,0x019E,
                      0x0191,0x019B,0x0199,0x0195,0x0190,0x019A,0x0198,0x0194 };
extern ULONG64 g_ExecCount2;
extern ULONG   g_codeDispatchAddr;
extern ULONG   g_user32_base;
extern ULONG   g_ntdll_base;
extern ULONG   g_kernel_base;
extern PVOID   *g_codeTable;
extern ULONG64 *g_pageState;

extern PVOID   *g_stateTable;
extern ULONG   g_auxPageBase;
extern ULONG   g_target_pid;

extern ULONG   g_threadCreateCount;
extern ULONG   g_threadExitCount;
extern KEVENT  g_procExitEvent;

extern PfnZwQueryVirtualMemory   pZwQueryVirtualMemory;
extern ULONG   g_debug_flag;

PVOID  AllocateFromUserSpaceCache(SIZE_T size);
PVOID  AllocateFromUserSpaceBufferEntries(ULONG va);


//lea ecx,[ecx + edx*4 + offset]  
ULONG g_emuLeaEcxTable[] = {0x00118C8D, 0x00118C8D, 0x00518C8D, 0x00000000,
                            0x00918C8D, 0x00000000, 0x00000000, 0x00000000, 
							0x00D18C8D };
//lea ecx, [ecx*2/4/8 + offset]  
ULONG g_emuLeaEcxIndexTable[] = { 0x00000000, 0x00000000, 0x004D0C8D, 0x00000000,
								  0x008D0C8D, 0x00000000, 0x00000000, 0x00000000, 
                                  0x00CD0C8D };

UCHAR g_emuCallJmpRetTempl[] = { 
	0x8B,0xD1,                           //mov         edx,ecx
	0xC1,0xE9,0x0C,                      //shr         ecx,0Ch  
	0x81,0xE2,0xFF,0x0F,0x00,0x00,       //and         edx,0FFFh  
	0x8B,0x0C,0x8D,0x00,0x00,0x00,0x00,  //mov         ecx,dword ptr [ecx*4 + g_codeTable]  
	0x8B,0x0C,0x91,                      //mov         ecx,dword ptr [ecx + edx*4] 
	0x64,0x89,0x0D,0x68,0x00,0x00,0x00,  //mov         dword ptr fs:[68h],ecx
//FAULT1:
	//0x04,0x7F,                           //add         al,7Fh
	//0x9E,                                //sahf
	//0x64,0x8B,0x15,0x7C,0x00,0x00,0x00,  //mov         edx,dword ptr fs:[7Ch] 
	//0x64,0x8B,0x0D,0x78,0x00,0x00,0x00,  //mov         ecx,dword ptr fs:[78h]
	//0x64,0xA1,0x70,0x00,0x00,0x00,       //mov         eax,dword ptr fs:[70h]
};


inline void memcpy_fast_16(void* dst, const void* src, size_t size)
{
	switch (size)
	{
	case 0: break;
	case 1: *(uint8_t*)dst = *(uint8_t*)src;
		break;
	case 2: *(uint16_t*)dst = *(uint16_t*)src;
		break;
	case 3:
		*(uint16_t*)dst = *(uint16_t*)src;
		*((uint8_t*)dst + 2) = *((uint8_t*)src + 2);
		break;
	case 4: *(uint32_t*)dst = *(uint32_t*)src;
		break;
	case 5:
		*(uint32_t*)dst = *(uint32_t*)src;
		*((uint8_t*)dst + 4) = *((uint8_t*)src + 4);
		break;
	case 6:
		*(uint32_t*)dst = *(uint32_t*)src;
		*(uint16_t*)((uint8_t*)dst + 4) = *(uint16_t*)((uint8_t*)src + 4);
		break;
	case 7:
		*(uint32_t*)dst = *(uint32_t*)src;
		*(uint32_t*)((uint8_t*)dst + 3) = *(uint32_t*)((uint8_t*)src + 3);
		break;
	case 8:
		*(uint64_t*)dst = *(uint64_t*)src;
		break;
	case 9:
		*(uint64_t*)dst = *(uint64_t*)src;
		*((uint8_t*)dst + 8) = *((uint8_t*)src + 8);
		break;
	case 10:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint16_t*)((uint8_t*)dst + 8) = *(uint16_t*)((uint8_t*)src + 8);
		break;
	case 11:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint32_t*)((uint8_t*)dst + 7) = *(uint32_t*)((uint8_t*)src + 7);
		break;
	case 12:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint32_t*)((uint8_t*)dst + 8) = *(uint32_t*)((uint8_t*)src + 8);
		break;
	case 13:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 5) = *(uint64_t*)((uint8_t*)src + 5);
		break;
	case 14:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 6) = *(uint64_t*)((uint8_t*)src + 6);
		break;
	case 15:
		*(uint64_t*)dst = *(uint64_t*)src;
		*(uint64_t*)((uint8_t*)dst + 7) = *(uint64_t*)((uint8_t*)src + 7);
		break;
	default:
		memcpy(dst, src, size); break;
	}
}


unsigned int DJBHash(char *str, unsigned int len)
{
	unsigned int hash = 5381;
	unsigned int i = 0;
	while (i < len) {
		hash = ((hash << 5) + hash) + (*str++); /* times 33 */
		i++;
	}
	hash &= ~(1 << 31); /* strip the highest bit */
	return hash;
}

void __stdcall EmuKiServiceCheckWait(THREAD_DATA *pThreadData, PKTRAP_FRAME pTrapFrame)
{
	BLOCK_PROFILER *pLastBlockProfiler = (BLOCK_PROFILER *)*(ULONG *)(pThreadData->Teb + TEB_PROFILER_OFFSET);

	if (pLastBlockProfiler && (pLastBlockProfiler->Syscall == LOG_SYSENTER_FLAG))
	{
		ULONG  block_ip = pTrapFrame->Eip;
		PVOID  codePage = g_codeTable[block_ip >> 12];
		if (((ULONG)codePage & 0xFFF00000) != ANALYSIS_CODE_FAULT_BASE)
		{
			ULONG codeBytesBase = *(ULONG *)((ULONG)codePage + (block_ip & 0xFFF) * 4);
			if (codeBytesBase != block_ip)
			{
				pTrapFrame->Eip = codeBytesBase;
			}			
		}
	}
}

void __stdcall EmuKiCallUserExitCheckWait(THREAD_DATA *pThreadData, ULONG block_ip)
{
	BLOCK_PROFILER *pLastBlockProfiler = (BLOCK_PROFILER *)*(ULONG *)(pThreadData->Teb + TEB_PROFILER_OFFSET);

	if (pLastBlockProfiler && (pLastBlockProfiler->Syscall == LOG_SYSENTER_FLAG))
	{
		//Temporarily unprocessed, edx as the target of sysexit.
	}
}

//KiFastCallEntry
VOID __stdcall EmuKiFastCallEntryHandler(PKTRAP_FRAME3 pTrapFrame)
{
	THREAD_DATA *pThreadData = GET_THREAD_DATA();
	if (pThreadData  && pThreadData->Start)
	{
		pThreadData->Syscall = 1;
		//DbgPrint("-{sysenter} thread %d, eax %x, edx %x\n", 
		//	pThreadData->tid, pTrapFrame->Eax, pTrapFrame->Edx);
	}
}

VOID __stdcall EmuKiServiceExitHandler(PKTRAP_FRAME pTrapFrame)
{
	THREAD_DATA *pThreadData = GET_THREAD_DATA();
	if (pThreadData && pThreadData->Start && (pTrapFrame->SegCs != 8)) //user mode
	{
		EmuKiServiceCheckWait(pThreadData, pTrapFrame);
		pThreadData->Syscall = 0;
		//DEBUG
		if (pTrapFrame->Eip == (g_ntdll_base + NTDLL_APC_DISPATCHER_OFFSET))     //ntdll!KiUserApcDispatcher
		{
			//DbgPrint("-{sysexit} APC. thread %d, kframe esp %x, eip %08x\n", pThreadData->Tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
		else if (pTrapFrame->Eip == (g_ntdll_base + NTDLL_CALLBACK_DISPATCHER_OFFSET)) //ntdll!KiUserCallbackDispatcher
		{
			//DbgPrint("-{sysexit} CALLBACK. thread %d, kframe esp %x, eip %08x\n", pThreadData->Tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
		else  //common sysexit
		{
			//DbgPrint("-{sysexit} thread %d, kframe esp %x, eip %08x\n", pThreadData->tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
		}
	}
}

VOID __stdcall EmuKiCallUserModeExitHandler(PKTRAP_FRAME pTrapFrame)
{
	THREAD_DATA *pThreadData = GET_THREAD_DATA();
	if (pThreadData && pThreadData->Start)
	{
		//DbgPrint("-{calluserexit}, kframe %08x, tid %d\n", pTrapFrame, pThreadData->Tid);
		//edx -> KiUserCallbackDispatcher 
		//EmuKiCallUserExitCheckWait(pThreadData, g_ntdll_base + NTDLL_CALLBACK_DISPATCHER_OFFSET);
		pThreadData->Syscall = 0;
	}
}

VOID __stdcall EmuKei386HelperExitHandler(PKTRAP_FRAME pTrapFrame)
{
	THREAD_DATA *pThreadData = GET_THREAD_DATA();
	if (pThreadData && pThreadData->Start && (pTrapFrame->SegCs != 8)) //user mode
	{
		if (pTrapFrame->Eip == (g_ntdll_base + NTDLL_APC_DISPATCHER_OFFSET)) //maybe
		{
			//DbgPrint("-{i386exit} APC. thread %d, kframe esp %x, dbgeip %08x\n", pThreadData->Tid,
			//	 pTrapFrame->HardwareEsp, pTrapFrame->DbgEip);
			EmuKiServiceCheckWait(pThreadData, pTrapFrame);
		}
		else if (pTrapFrame->Eip == (g_ntdll_base + NTDLL_EXCEPTION_DISPATCHER_OFFSET)) //ntdll!KiUserExceptionDispatcher
		{
			//DbgPrint("-{i386exit} EXCEPT. thread %d, kframe esp %x, eip %08x\n", pThreadData->Tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
			EmuKiServiceCheckWait(pThreadData, pTrapFrame);
		}
		else if (pTrapFrame->Eip == (g_user32_base + USER32_CLIENT_THREAD_OFFSET)) //user32!__ClientThreadSetup
		{
			//DbgPrint("-{i386exit} USER32. thread %d, kframe esp %x, eip %08x\n", pThreadData->Tid,
			//	pTrapFrame->HardwareEsp, pTrapFrame->Eip);
			EmuKiServiceCheckWait(pThreadData, pTrapFrame);
		}
		else if (pTrapFrame->DbgEip != pTrapFrame->Eip)       //ntdll!NtContinue
		{
			//DbgPrint("-{i386exit} CONT. thread %d, kframe esp %x, dbgeip %08x, eip %08x\n",
			//	pThreadData->Tid, pTrapFrame->HardwareEsp, pTrapFrame->DbgEip, pTrapFrame->Eip);
			EmuKiServiceCheckWait(pThreadData, pTrapFrame);
		}
		else //CHECK
		{
			//BLOCK_PROFILER *pLastBLockProfiler = (BLOCK_PROFILER *)*(ULONG *)(pThreadData->Teb + TEB_PROFILER_OFFSET);
			//if (pLastBLockProfiler && (pLastBLockProfiler->Syscall == LOG_SYSENTER_FLAG))
			//{
			//	DbgPrint("-{i386exit} TRAP. thread %d, kframe esp %x, syscall %d, eip %08x\n",
			//		pThreadData->Tid, pTrapFrame->HardwareEsp,
			//		pThreadData->Syscall, pTrapFrame->Eip);
			//}
			//if (pThreadData->Syscall) //From KiFastCallEntry
			//{	
			//	DbgPrint("-{i386exit} CHECK. thread %d, kframe esp %x, syscall %d, eip %08x\n",
			//		pThreadData->Tid, pTrapFrame->HardwareEsp,
			//		pThreadData->Syscall, pTrapFrame->Eip);
			//}
		}
		pThreadData->Syscall = 0;
	}
}

#pragma optimize( "gt", on )

UCHAR * _stdcall OpBlockAnalysisCallJmpRet(UCHAR *codePtr, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	if (cacheLen)
	{
		//Place the analysis code first
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
	}
	//Restore context
	*(UINT32 *)(codePtr) = 0x9E7F04;         //add al, 7Fh; sahf
	*(UINT32 *)(codePtr + 3) = 0x7C158B64;   //mov edx, fs:[7Ch]
	*(UINT32 *)(codePtr + 7) = 0x64000000;   //mov ecx, fs:[78h]  
	*(UINT32 *)(codePtr + 11) = 0x00780D8B;  //mov eax, fs:[70h]
	*(UINT32 *)(codePtr + 15) = 0xA1640000;
	*(UINT32 *)(codePtr + 19) = 0x00000070;
	codePtr += 23;

	return codePtr;
}

UCHAR * _stdcall OpBlockAnalysisCommon(UCHAR *codePtr, UCHAR *cacheBase, UCHAR **pCachePtr, ULONG hasMemOp)
{
	ULONG  cacheLen = (*pCachePtr) - cacheBase;

	if (cacheLen)
	{
		if (hasMemOp)
		{
			*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
			*(UINT32 *)(codePtr + 20) = 0xC0900F9F;       //lahf; seto al
			codePtr += 24;
			memcpy(codePtr, cacheBase, cacheLen);
			codePtr += cacheLen;
			*(UINT32 *)(codePtr) = 0x9E7F04;         //add al, 7Fh; sahf
			*(UINT32 *)(codePtr + 3) = 0x7C158B64;   //mov edx, fs:[7Ch]
			*(UINT32 *)(codePtr + 7) = 0x64000000;   //mov ecx, fs:[78h]  
			*(UINT32 *)(codePtr + 11) = 0x00780D8B;  //mov eax, fs:[70h]
			*(UINT32 *)(codePtr + 15) = 0xA1640000;
			*(UINT32 *)(codePtr + 19) = 0x00000070;
			codePtr += 23;
		}
		else
		{
			*(UINT64 *)(codePtr)     = 0x896400000070A364; //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x900F9F0000007C15; //mov fs:[7Ch], edx
			*(UINT8 *)(codePtr + 16) = 0xC0;               //lahf; seto al
			codePtr += 17;
			memcpy(codePtr, cacheBase, cacheLen);
			codePtr += cacheLen;
			*(UINT64 *)(codePtr)     = 0x007C158B649E7F04; //add al, 7Fh; sahf; mov edx, fs:[7Ch]
			*(UINT64 *)(codePtr + 8) = 0x00000070A1640000; //mov eax, fs:[70h]
			codePtr += 16;
		}
		*pCachePtr = cacheBase;
	}

	return codePtr;
}

UCHAR * _stdcall OpBlockAnalysisOpWrite(UCHAR *codePtr, UCHAR *cacheBase, UCHAR **pCachePtr)
{
	ULONG  cacheLen = (*pCachePtr) - cacheBase;
	
	if (cacheLen)
	{
		*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
		*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
		*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
		*(UINT32 *)(codePtr + 20) = 0xC0900F9F;       //lahf; seto al
		codePtr += 24;
		memcpy(codePtr, cacheBase, cacheLen);
		codePtr += cacheLen;
		*pCachePtr = cacheBase;
		*(UINT32 *)(codePtr) = 0x9E7F04;         //add al, 7Fh; sahf
		*(UINT32 *)(codePtr + 3) = 0x7C158B64;   //mov edx, fs:[7Ch]
		*(UINT32 *)(codePtr + 7) = 0x64000000;   //mov ecx, fs:[78h]  
		*(UINT32 *)(codePtr + 11) = 0x00780D8B;  //mov eax, fs:[70h]
		*(UINT32 *)(codePtr + 15) = 0xA1640000;
		*(UINT32 *)(codePtr + 19) = 0x00000070;
		codePtr += 23;
	}

	return codePtr;
}

PVOID __stdcall GetAllocBlockProfiler(PROCESSOR_DATA *processorData, ULONG  faultIp)
{
	ULONG  vpfn = faultIp >> 12;
	ULONG  codePage = (ULONG)g_codeTable[vpfn];

	if (((ULONG)codePage & 0xFFF00000) == ANALYSIS_CODE_FAULT_BASE)
	{
		//Physical pages may not been allocated.
		codePage = (ULONG)AllocateFromUserSpaceCache(PAGE_SIZE * 4);
		g_codeTable[faultIp >> 12] = (PVOID)((ULONG)codePage & 0xFFFFF000);
		for (ULONG i = 0; i < PAGE_SIZE; i++)
		{
			((PULONG)codePage)[i] = (faultIp & 0xFFFFF000) + i;
		}
		ULONG initCodePage = ANALYSIS_CODE_FAULT_BASE + vpfn;
		ULONG oldCodePage = InterlockedCompareExchange((LONG *)(g_codeTable + vpfn),
			(LONG)(codePage & 0xFFFFF000), initCodePage);
		if (oldCodePage == initCodePage)
		{
			g_ExecCount2++;
		}
	}

	ULONG           mapAddr = codePage + (faultIp & 0xFFF) * 4;
	ULONG           existedCodeBase = *(ULONG *)mapAddr;
	BLOCK_PROFILER *pProfiler = NULL;

	if (existedCodeBase != faultIp)
	{
		pProfiler = (BLOCK_PROFILER *)*(ULONG *)(existedCodeBase + 5); //nop word ptr [eax+eax+77662211h] 
	}
	else   //Alloacate profiler in advance
	{
		if (((ULONG)processorData->HdBufPtr + 0x100) > (processorData->HdBufBase + PER_CPU_HEAD_BUF_SIZE))
		{
			DbgPrint("[CHECK] GetAllocBlockProfiler. HdBufBase %x, HdBufPtr %x %x\n",
				processorData->HdBufBase, processorData->HdBufPtr);
			__debugbreak();
			ZwTerminateProcess(NtCurrentProcess(), 1);
		}
		pProfiler = (BLOCK_PROFILER *)processorData->HdBufPtr;
		memset(pProfiler, 0, sizeof(BLOCK_PROFILER));
		pProfiler->FaultIp = faultIp;
		//stub, 9 bytes
		UCHAR *pStubCode = (UCHAR *)((ULONG)processorData->HdBufPtr + sizeof(BLOCK_PROFILER));
		*(UINT8 *)(pStubCode) = 0xE9;                   //jmp  OriginBlockIp;
		*(UINT32 *)(pStubCode + 1) = faultIp - ((ULONG)pStubCode) - 5;
		*(UINT32 *)(pStubCode + 5) = (UINT32)pProfiler; //+5 profiler
		//update
		existedCodeBase = InterlockedCompareExchange((LONG *)mapAddr, (LONG)pStubCode, faultIp);
		if (existedCodeBase == faultIp)
		{
			processorData->HdBufPtr += sizeof(BLOCK_PROFILER) + 9;
			KeInitializeSpinLock(&pProfiler->Lock);
		}
		else
		{
			pProfiler = (BLOCK_PROFILER *)*(ULONG *)(existedCodeBase + 5);
		}
	}

	return pProfiler;
}

void __stdcall ParseBuildBlock(PROCESSOR_DATA *processorData, BLOCK_PROFILER *blockProfiler, ULONG *forward)
{
	ud_t   *p_ud = &processorData->UdObj;
	const   ud_operand_t* opr0 = &p_ud->operand[0];
	const   ud_operand_t* opr1 = &p_ud->operand[1];
	const   ud_operand_t* opr2 = &p_ud->operand[2];
	UCHAR   *codePtr = (UCHAR *)processorData->CodePtr;
	ULONG   curIp = processorData->DisIp;

	//For locally caching the analysis code
	UCHAR   *cacheBase = (UCHAR *)processorData->TmpBufPtr;
	UCHAR   *cachePtr = cacheBase;

	ULONG   farAddr = 0;
	ULONG   nearAddr = 0;
	ULONG   disLen = 0;

	ULONG   insCount = 0; 
	ULONG   recIndex = 0;
	UCHAR   bh0, bi0, bh1, bi1;

	//Check the boundary
	if ((codePtr + PAGE_SIZE) > (UCHAR *)(processorData->BufBase + PER_CPU_CODE_BUF_SIZE))
	{
		DbgPrint("[CHECK] BufBase %x, codePtr %x\n", processorData->BufBase, codePtr);
		__debugbreak();
		ZwTerminateProcess(NtCurrentProcess(), 1);
	}

	ULONG hasRead = 0, hasWrite = 0;

	ud_set_input_buffer(p_ud, (uint8_t *)curIp, 2 * PAGE_SIZE);
	while (true)
	{
		insCount++;
		//Cross-page conditions may occur, processed in the #PF handler
		disLen = ud_decode(p_ud);
		//Some bugs with udis86
		if (p_ud->mnemonic == UD_Ivpsllq)
		{
			if (*(UCHAR *)(curIp + 2) == 0x73) //vpsllq  xmm2,xmm4,2Ah
			{
				disLen = 5;
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				//Reset p_ud
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
		}
		if (!disLen || (p_ud->mnemonic == UD_Iinvalid))
		{
			DbgPrint("[CHECK] Decode error. disLen %d, mnemonic %d, profiler %x, start %x, curIp %x, codePtr %x\n",
				disLen, p_ud->mnemonic, blockProfiler, processorData->DisIp, curIp, codePtr);
			//udis86 bug
			if ((*(USHORT *)curIp == 0xfdc5) || //pscp: vpmovmskb eax,ymm0
				(*(USHORT *)curIp == 0xf5c5))  //vpcmpeqb ymm0,ymm1,ymmword ptr [ecx]
			{
				disLen = 4;
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe3c4) //xz_r: vinserti128 ymm7,ymm0,xmm1,0
			{
				disLen = 6;
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe5c5) //xz_r: vpslld  ymm0,ymm3,xmm7
			{
				disLen = 4;
				if (*(USHORT *)(curIp + 2) == 0x0ddb) //vpand   ymm1,ymm3,ymmword ptr ds:[xxxx]
				{
					disLen = 8;
				}
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xfdc5) //xz_r:   vpslld  ymm2,ymm0,xmm5
			{                                    //x264_r: vpmovmskb eax, ymm0
				disLen = 4;
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else if (*(USHORT *)curIp == 0xe2c4) //perlbench_r: shlx ecx,edx,ebx; blsr eax,edi
			{
				disLen = 5; //andn  eax,eax,ecx
				if (*(USHORT *)(curIp + 4) == 0x2484)     //shlx eax,[esp+800000h],eax
				{
					disLen = 10;
				}
				else if (*(USHORT *)(curIp + 4) == 0x2444) //shlx eax,[esp+40h],eax
				{
					disLen = 7;
				}
				else if (*(USHORT *)(curIp + 4) == 0x2464) //vpbroadcastd ymm4,dword ptr [esp+48h]
				{
					disLen = 7;
				}
				else if (*(USHORT *)(curIp + 2) == 0x5979) //vpbroadcastq xmm0,mmword ptr ds:[0EF4ED8h]
				{
					disLen = 9;
				}
				else if (*(USHORT *)(curIp + 3) == 0x1c58) //vpbroadcastd ymm3,dword ptr [ecx+eax]
				{
					disLen = 6;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x80f7) || //sarx  eax, dword ptr[eax + 64000440h], ecx
					(*(USHORT *)(curIp + 3) == 0x86f7) || //x264_r: shlx eax,dword ptr [esi+28C0h],eax
					(*(USHORT *)(curIp + 3) == 0x87f7) || //        shlx eax,dword ptr [edi+28C0h],ecx
					(*(USHORT *)(curIp + 3) == 0x8af7) || //xz_r: sarx  ecx,dword ptr [edx+494h],eax
					(*(USHORT *)(curIp + 3) == 0x96f7))   //xz_r: shrx  edx,dword ptr [esi+134h],eax
				{
					disLen = 9;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x4cf7) || //xz_r: 
					(*(USHORT *)(curIp + 3) == 0x44f7))   //x264_r: shlx eax,dword ptr [esp+28h],esi
				{
					disLen = 7;
				}
				else if ((*(USHORT *)(curIp + 3) == 0x42f7) ||  //x264_r: sarx  eax,dword ptr [edx+18h],eax
					(*(USHORT *)(curIp + 3) == 0x46f7) || //x264_r: sarx eax,dword ptr [esi+18h],edx
					(*(USHORT *)(curIp + 3) == 0x47f7) || //x264_r: shlx  eax,dword ptr [edi+0Ch],ebx
					(*(USHORT *)(curIp + 3) == 0x4ff7) || //x264_r: shlx  ecx,dword ptr [edi+0Ch],eax
					(*(USHORT *)(curIp + 3) == 0x52f7) || //x264_r: sarx  edx,dword ptr [edx+14h],eax
					(*(USHORT *)(curIp + 3) == 0x56f7) ||    //x264_r: shlx  edx,dword ptr [esi+0Ch],edi
					(*(USHORT *)(curIp + 3) == 0x77f7) || //shlx    esi,dword ptr [edi+64h],ecx
					(*(USHORT *)(curIp + 3) == 0x04f7) || //shlx    eax,dword ptr [ecx+edx],edi
					(*(USHORT *)(curIp + 3) == 0x0cf7) || //shlx    ecx,dword ptr [ecx+eax],edi
					(*(USHORT *)(curIp + 3) == 0x14f7)    //shlx    edx,dword ptr [esi+eax],ecx
					)
				{
					disLen = 6;
				}
				memcpy_fast_16(codePtr, (void *)curIp, disLen);
				codePtr += disLen;
				curIp += disLen;
				blockProfiler->BlockSize += disLen;
				ud_set_input_buffer(p_ud, (uint8_t *)curIp, 4 * PAGE_SIZE);
				continue;
			}
			else
			{
				DbgPrint("[CHECK] Decode error. disLen %d, mnemonic %d, profiler %x, start %x, curIp %x\n",
					disLen, p_ud->mnemonic, blockProfiler, processorData->DisIp, curIp);
				__debugbreak();
			}
		}
		blockProfiler->BlockSize += disLen;
		//Util branch instructions
		if (opr0->type == UD_OP_JIMM) //jcc/jmp rel;call rel32
		{
			//Place previously cached code
			codePtr = OpBlockAnalysisCommon(codePtr, cacheBase, &cachePtr, (hasRead | hasWrite));
			switch (opr0->size)
			{
			case 8:
				farAddr = curIp + opr0->lval.sbyte + disLen;
				nearAddr = curIp + disLen;
				break;
			case 16:
				farAddr = curIp + opr0->lval.sword + disLen;
				nearAddr = curIp + disLen;
				break;
			case 32:
				farAddr = curIp + opr0->lval.sdword + disLen;
				nearAddr = curIp + disLen;
				break;
			default:
				__debugbreak();
			}
			switch (p_ud->mnemonic)
			{
			case UD_Icall:           //far call and retf?
				*codePtr = 0x68;
				*(UINT32 *)(codePtr + 1) = nearAddr; //push
				codePtr += 5;
				*(UINT8 *)codePtr = 0xE9;            //jmp
				*(UINT32 *)(codePtr + 1) = farAddr - (UINT32)codePtr - 5;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 1);
				blockProfiler->BranchOffset2 = 0;
				codePtr += 5;
				*forward = 0; //flag
				break;
			case UD_Ijmp:
				*(UINT8 *)codePtr = 0xE9;     
				*(UINT32 *)(codePtr + 1) = farAddr - (UINT32)codePtr - 5;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 1);
				blockProfiler->BranchOffset2 = 0;
				codePtr += 5;
				*forward = 0; 
				break;
			case UD_Ijecxz:   //ecx = 0
				*(UINT16 *)codePtr = 0x05E3;
				*(UINT8 *)(codePtr + 2) = 0xE9;
				*(UINT32 *)(codePtr + 3) = nearAddr - (UINT32)(codePtr + 2) - 5;
				blockProfiler->BranchOffset2 = (ULONG)(codePtr + 3);
				*(UINT8 *)(codePtr + 7) = 0xE9;
				*(UINT32 *)(codePtr + 8) = farAddr - (UINT32)(codePtr + 7) - 5;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 8);
				codePtr += 12;
				*forward = 0; 
				DbgPrint("[INFO] UD_Ijecxz type %x, curIp %x\n", p_ud->mnemonic, curIp);
				break;
			case UD_Ijo:    //of = 1, 0f 80
				*(UINT16 *)codePtr = 0x800F; 
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijno:   //of = 0, 0f 81
				*(UINT16 *)codePtr = 0x810F;  
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijb:   //cf = 1 , jc, jnae 0f 82
				*(UINT16 *)codePtr = 0x820F;   
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijae:  //cf = 0, jnb,jnc 0f 83
				*(UINT16 *)codePtr = 0x830F;     
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijz: //zf = 1, je, 0f 84
				*(UINT16 *)codePtr = 0x840F;   
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijnz:   //zf = 0, jne,jnz 0f 85
				*(UINT16 *)codePtr = 0x850F;   
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9;
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijbe:  //cf = 1 or zf = 1, jna, 0f 86
				*(UINT16 *)codePtr = 0x860F;    
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ija:   //cf = 0 and zf = 0, jnbe, 0f 87
				*(UINT16 *)codePtr = 0x870F;    
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijs: //sf = 1, 0f 88
				*(UINT16 *)codePtr = 0x880F;  
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9;
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijns:   //sf = 0, 0f 89
				*(UINT16 *)codePtr = 0x890F; 
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9;
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijp:    //pf = 1, jpe, 0f 8a
				*(UINT16 *)codePtr = 0x8A0F;
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijnp:   //pf = 0, jpo, 0f 8b
				*(UINT16 *)codePtr = 0x8B0F; 
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijl:    //sf != 0F, jnge, 0f 8c
				*(UINT16 *)codePtr = 0x8C0F;  
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijge:   //sf = of, jnl, 0f 8d
				*(UINT16 *)codePtr = 0x8D0F;   
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijle:   //zf = 1 or sf != of, jng, 0f 8e
				*(UINT16 *)codePtr = 0x8E0F; 
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward)) 
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			case UD_Ijg:   //zf = 0 and sf = of, jnle 0f 8f
				*(UINT16 *)codePtr = 0x8F0F; 
				*(UINT32 *)(codePtr + 2) = farAddr - (UINT32)codePtr - 6;
				blockProfiler->BranchOffset1 = (ULONG)(codePtr + 2);
				if (!(*forward))
				{
					*(UINT8 *)(codePtr + 6) = 0xE9; 
					*(UINT32 *)(codePtr + 7) = nearAddr - (UINT32)(codePtr + 6) - 5;
					blockProfiler->BranchOffset2 = (ULONG)(codePtr + 7);
					codePtr += 11;
				}
				else
				{
					blockProfiler->BranchOffset2 = 0;
					codePtr += 6;
				}
				break;
			default: 
				DbgPrint("[CHECK] Unknown type %d, start %x cur_ip %x\n", p_ud->mnemonic, processorData->DisIp, curIp);
				__debugbreak();
			}
			curIp += disLen;
			break;
		}
		else if (p_ud->mnemonic == UD_Icall)
		{
			*(UINT64 *)(codePtr) = 0x896400000070A364;    //mov fs:[70h], eax
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;//mov fs:[78h], ecx
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       //mov fs:[7Ch], edx
			codePtr += 20;
			if (opr0->type == UD_OP_MEM) //call [esp+8]
			{
				if (p_ud->pfx_seg) //call -> mov ecx, cs:[xxxxx]
				{
					memcpy_fast_16(codePtr, (void *)curIp, disLen); 
					*(UINT8 *)(codePtr + 1) = 0x8B;
					*(UINT8 *)(codePtr + 2) -= 8;
					codePtr += disLen;
				}
				else
				{
					memcpy_fast_16(codePtr, (void *)curIp, disLen);  //call -> mov ecx, [xxxxx]
					*(UINT8 *)(codePtr) = 0x8B;
					*(UINT8 *)(codePtr + 1) -= 8;
					codePtr += disLen;
				}
			}
			else
			{
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) = (opr0->base - UD_R_EAX) + 0xC8; //mov ecx, REG0
				codePtr += 2;
			}
			*(UINT64 *)(codePtr) = 0x000000680D8964;   //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 7) = 0xC0900F9F;     //lahf; seto al
			codePtr += 11;
			memcpy(codePtr, g_emuCallJmpRetTempl, sizeof(g_emuCallJmpRetTempl));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_codeTable;
			codePtr += sizeof(g_emuCallJmpRetTempl);
	
			codePtr = OpBlockAnalysisCallJmpRet(codePtr, cacheBase, &cachePtr);
			//push
			*(UINT8 *)(codePtr) = 0x68;
			*(UINT32 *)(codePtr + 1) = curIp + disLen;
			*(UINT32 *)(codePtr + 5) = 0x6825FF64;      //jmp fs:[68h] 
			*(UINT32 *)(codePtr + 9) = 0x00000000;
			codePtr += 12; //5+7
			*forward = 0;
			curIp += disLen;
			break;
		}
		else if (p_ud->mnemonic == UD_Ijmp)  //jmp [ebx+8]; ff /4,
		{
			*(UINT64 *)(codePtr) = 0x896400000070A364;   
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       
			codePtr += 20;
			if (opr0->type == UD_OP_MEM) //jmp [esp+8]
			{
				memcpy_fast_16(codePtr, (void *)curIp, disLen); //jmp -> mov ecx, [xxxxx]
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) -= 0x18;
				codePtr += disLen;
			}
			else
			{
				*(UINT8 *)(codePtr) = 0x8B;
				*(UINT8 *)(codePtr + 1) = (opr0->base - UD_R_EAX) + 0xC8; //mov ecx, REG0
				codePtr += 2;
			}
			*(UINT64 *)(codePtr) = 0x000000680D8964;   //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 7) = 0xC0900F9F;     //lahf; seto al
			codePtr += 11;
			memcpy(codePtr, g_emuCallJmpRetTempl, sizeof(g_emuCallJmpRetTempl));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_codeTable;
			codePtr += sizeof(g_emuCallJmpRetTempl);

			codePtr = OpBlockAnalysisCallJmpRet(codePtr, cacheBase, &cachePtr);
			*(UINT32 *)(codePtr) = 0x6825FF64;
			*(UINT32 *)(codePtr + 4) = 0x00000000;
			codePtr += 7;
			*forward = 0;
			curIp += disLen;
			break;
		}
		else if (p_ud->mnemonic == UD_Iret)
		{
			*(UINT64 *)(codePtr) = 0x896400000070A364;    
			*(UINT64 *)(codePtr + 8) = 0x158964000000780D;
			*(UINT32 *)(codePtr + 16) = 0x0000007C;       
			*(UINT32 *)(codePtr + 20) = 0x240C8B;         //mov ecx, [esp]
			*(UINT64 *)(codePtr + 23) = 0x000000680D8964; //mov  fs:[68h], ecx
			*(UINT32 *)(codePtr + 30) = 0xC0900F9F;      
			codePtr += 34;
			memcpy(codePtr, g_emuCallJmpRetTempl, sizeof(g_emuCallJmpRetTempl));
			*(UINT32 *)(codePtr + 14) = (ULONG)g_codeTable;
			codePtr += sizeof(g_emuCallJmpRetTempl);

			codePtr = OpBlockAnalysisCallJmpRet(codePtr, cacheBase, &cachePtr);
			*(UINT64 *)(codePtr) = 0x0000000424A48D; //lea esp, [esp+4]
			if (opr0->type == UD_OP_IMM)             //ret imm16
			{
				*(UINT32 *)(codePtr + 3) = opr0->lval.uword + 4;
			}
			*(UINT32 *)(codePtr + 7) = 0x6825FF64;
			*(UINT32 *)(codePtr + 11) = 0x000000;
			codePtr += 14;
			*forward = 0;
			curIp += disLen;
			break;
		}
		else if (p_ud->mnemonic == UD_Isysenter)
		{
			codePtr = OpBlockAnalysisCommon(codePtr, cacheBase, &cachePtr, hasRead | hasWrite);
			//Syscall indicator
			*(UINT32 *)(codePtr) = 0x5005C764;  
			*(UINT32 *)(codePtr + 3) = TEB_PROFILER_OFFSET;
			*(UINT32 *)(codePtr + 7) = (UINT32)blockProfiler;
			codePtr += 11;

			memcpy_fast_16(codePtr, (void *)curIp, disLen);
			codePtr += disLen;
			blockProfiler->Syscall = LOG_SYSENTER_FLAG;
			*forward = 0; 
			curIp += disLen;
			break;
		}
		else //Test without analysis
		{
			memcpy_fast_16(codePtr, (void *)curIp, disLen);
			codePtr += disLen;
			curIp += disLen;
			continue;
		}
		//if (p_ud->pfx_seg == UD_R_FS)   //mov eax, fs:[30h]£» mov fs:[eax], 20£¬ skip
		//{
		//	memcpy_fast_16(codePtr, (void *)curIp, disLen);
		//	codePtr += disLen;
		//	curIp += disLen;
		//	continue;
		//}
		/*switch (p_ud->mnemonic)
		{
		case UD_Iadc:
		case UD_Iadd:
		case UD_Iand:
		case UD_Ior:
		case UD_Isbb:
		case UD_Isub:
		case UD_Ixor:
			if (opr1->type == UD_OP_IMM)
			{
				break;
			}
			if (opr1->type == UD_OP_MEM)  //add  ebx, [esp+8]
			{
			}
			else if (opr0->type == UD_OP_MEM) //adc  [esp+8], ebx
			{
			}
			else //add ebx, eax 
			{
			}
			break;
		//.....
		default:
			break;
		}
		memcpy_fast_16(codePtr, (void *)curIp, disLen);
		codePtr += disLen;
		curIp += disLen;*/
	}

	if (blockProfiler->BranchOffset1) 
	{
		//Get and allocate the far block
		BLOCK_PROFILER *farProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, farAddr);
		if (farProfiler->CodeBytesPtr) //If it has been resolved, link directly
		{
			InterlockedExchange((LONG *)blockProfiler->BranchOffset1,
				farProfiler->CodeBytesPtr - blockProfiler->BranchOffset1 - 4);
		}
		else  //Add the current block to the FromList first
		{		
			FROM_NODE *pNode = (FROM_NODE *)processorData->HdBufPtr;
			processorData->HdBufPtr += sizeof(FROM_NODE);
			pNode->Profiler = blockProfiler;
			ExInterlockedPushEntryList(&farProfiler->FromListHead, &pNode->ListEntry, &farProfiler->Lock);
		}	
	}
	if (blockProfiler->BranchOffset2) //Indirect jump
	{	
		BLOCK_PROFILER *nearProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, nearAddr);
		if (nearProfiler->CodeBytesPtr)
		{
			InterlockedExchange((LONG *)blockProfiler->BranchOffset2,
				nearProfiler->CodeBytesPtr - blockProfiler->BranchOffset2 - 4);
		}
		else
		{
			FROM_NODE *pNode = (FROM_NODE *)processorData->HdBufPtr;
			processorData->HdBufPtr += sizeof(FROM_NODE);
			pNode->Profiler = blockProfiler;
			ExInterlockedPushEntryList(&nearProfiler->FromListHead, &pNode->ListEntry, &nearProfiler->Lock);
		}	
	}

	//Update the parse progress
	processorData->DisIp = curIp;
	processorData->CodePtr = codePtr;

	processorData->Counter1 += insCount;
}

ULONG __stdcall FaultCodePageRewritingBlock(PROCESSOR_DATA *processorData,
	THREAD_DATA *pThreadData, ULONG faultIp)
{
	ULONG pageState = (ULONG)g_pageState[faultIp >> 12];
	if (!(pageState & 0x1))     //byte0_executed = 0
	{
		InterlockedExchange8((CHAR *)&g_pageState[faultIp >> 12], 1);
		ULONG  pte = 0xC0000000 + (((ULONG)(faultIp & 0xFFFFF000) >> 9) & 0x7ffff8);
		ULONG  pa = *(ULONG *)pte;
		*(UCHAR *)((USHORT *)&g_pageState[faultIp >> 12] + 1) = (UCHAR)((pa >> 1) & 1);
		pa &= ~2UL;
		*(ULONG *)pte = pa;   //bit1 = 0
		__invlpg((PVOID)faultIp);
	}
	else if (pageState & 0x100) //byte1_written = 1
	{
		InterlockedExchange8(((CHAR *)&g_pageState[faultIp >> 12] + 1), 0);
		ULONG  pte = 0xC0000000 + (((ULONG)(faultIp & 0xFFFFF000) >> 9) & 0x7ffff8);
		ULONG  pa = *(ULONG *)pte;
		*(UCHAR *)((USHORT *)&g_pageState[faultIp >> 12] + 1) = (UCHAR)((pa >> 1) & 1);
		pa &= ~2UL;
		*(ULONG *)pte = pa;   //bit1 = 0
		__invlpg((PVOID)faultIp);
	}

	//Get profiler
	BLOCK_PROFILER *pBlockProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, faultIp);
	
	if (pBlockProfiler->CodeBytesPtr)   //Parsed
	{
		if (pBlockProfiler->Flag == 1)  //Rollback
		{
			ULONG codeBase = pBlockProfiler->CodeBytesPtr;
			ULONG blockHash = DJBHash((char *)faultIp, pBlockProfiler->BlockSize);
			if (blockHash != pBlockProfiler->BlockHash)
			{		
				pBlockProfiler->Syscall = 0;
				pBlockProfiler->BlockSize = 0;
				pBlockProfiler->BlockHash = 0;

				ULONG newCodeBase = processorData->BufPtr;
				processorData->CodePtr = (UCHAR *)processorData->BufPtr;
				processorData->DisIp = faultIp;
				ULONG  forward = 0; //Only one
				ParseBuildBlock(processorData, pBlockProfiler, &forward);

				pBlockProfiler->BlockHash = DJBHash((char *)faultIp, pBlockProfiler->BlockSize);
				//Patch
				pBlockProfiler->DynamicCodePtr = newCodeBase;
				*(UINT8 *)(codeBase) = 0xE9;   //jmp   NewCodeBytes
				InterlockedExchange((LONG *)(codeBase + 1), newCodeBase - (ULONG)codeBase-5);
				processorData->BufPtr = (ULONG)processorData->CodePtr;
			}
			else
			{
				InterlockedExchange16((SHORT *)&pBlockProfiler->Flag, 0);
				if (pBlockProfiler->DynamicCodePtr)
				{
					InterlockedExchange8((CHAR *)codeBase, 0xE9); //jmp   DynamicCodePtr   
					*(UINT32 *)(codeBase + 1) = pBlockProfiler->DynamicCodePtr - (ULONG)codeBase - 5;
				}
				else
				{
					InterlockedExchange((LONG *)codeBase, 0x841F0F66); //nop  word ptr [eax + eax + ]
					*(UINT8 *)(codeBase + 4) = 0x00;
				}			
			}
		}
	}
	else //first
	{
		ULONG  parseCount = PARSE_BLOCK_SEQ_NUM;  //
		ULONG  fwCodeBase[4] = { 0 };
		ULONG  fwCreated = 0;

		processorData->CodePtr = (UCHAR *)processorData->BufPtr;
		processorData->DisIp = faultIp;
		BLOCK_PROFILER *pProfiler = pBlockProfiler;
		ULONG           codeBase = (ULONG)processorData->CodePtr;
		while (parseCount)
		{
			//nop word ptr [eax+eax+PROFILER], header
			*(UINT32 *)(processorData->CodePtr) = 0x841F0F66;
			*(UINT8 *)(processorData->CodePtr + 4) = 0x00;
			*(UINT32 *)(processorData->CodePtr + 5) = (UINT32)pProfiler; //+5 profiler
			processorData->CodePtr += 9;

			ULONG  forward = 0;
			parseCount = parseCount - 1; //2-1 = 1; 1-1 = 0
			if (parseCount)
			{
				forward = 1;
			}
			ParseBuildBlock(processorData, pProfiler, &forward);
			if (!forward)
			{
				break;
			}
			pProfiler = (BLOCK_PROFILER *)GetAllocBlockProfiler(processorData, processorData->DisIp);
			if (pProfiler->CodeBytesPtr) 
			{
				*(UINT8 *)(processorData->CodePtr) = 0xE9;  //jmp  nearCodeBase
				*(UINT32 *)(processorData->CodePtr + 1) = pProfiler->CodeBytesPtr - (UINT32)(processorData->CodePtr) - 5;
				processorData->CodePtr += 5;
				break;
			}
			fwCodeBase[fwCreated++] = (ULONG)processorData->CodePtr;
		}

		LONG existedCode = InterlockedCompareExchange((LONG *)&pBlockProfiler->CodeBytesPtr, (LONG)codeBase, 0);
		if (existedCode == 0)
		{
			ULONG  mapAddr = (ULONG)g_codeTable[faultIp >> 12] + (faultIp & 0xFFF) * 4;
			InterlockedExchange((LONG *)mapAddr, codeBase);       
			processorData->BufPtr = (ULONG)processorData->CodePtr;
			pBlockProfiler->BlockHash = DJBHash((char *)pBlockProfiler->FaultIp, pBlockProfiler->BlockSize);

			for (ULONG i = 0; i < fwCreated; i++)
			{
				ULONG base = fwCodeBase[i];
				BLOCK_PROFILER *pfl = (BLOCK_PROFILER *)*(ULONG *)(base + 5);
				pfl->BlockHash = DJBHash((char *)pfl->FaultIp, pfl->BlockSize);
				ULONG cp = (ULONG)g_codeTable[pfl->FaultIp >> 12];
				if (cp == NULL)
				{
					__debugbreak();
				}
				ULONG  mpa = cp + (pfl->FaultIp & 0xFFF) * 4;
				InterlockedExchange((LONG *)&pfl->CodeBytesPtr, base);
				InterlockedExchange((LONG *)mpa, base);

				processorData->Counter3++;
			}

			processorData->Counter2++;
		}
	}

	while (1)
	{
		PSINGLE_LIST_ENTRY pEntry = ExInterlockedPopEntryList(&pBlockProfiler->FromListHead, &pBlockProfiler->Lock);
		if (!pEntry)
		{
			break;
		}
		BLOCK_PROFILER *fromProfiler = CONTAINING_RECORD(pEntry, FROM_NODE, ListEntry)->Profiler;
		if (fromProfiler->BranchOffset1)
		{
			InterlockedCompareExchange((LONG *)fromProfiler->BranchOffset1,
				pBlockProfiler->CodeBytesPtr - fromProfiler->BranchOffset1 - 4,
				pBlockProfiler->FaultIp - fromProfiler->BranchOffset1 - 4);
		}
		if (fromProfiler->BranchOffset2)
		{
			InterlockedCompareExchange((LONG *)fromProfiler->BranchOffset2,
				pBlockProfiler->CodeBytesPtr - fromProfiler->BranchOffset2 - 4,
				pBlockProfiler->FaultIp - fromProfiler->BranchOffset2 - 4);
		}
	}

	return pBlockProfiler->CodeBytesPtr;
}

#pragma optimize( "", off )

void __stdcall  MySwapContextHandler(PVOID kpcr, PVOID ethread, PVOID gdt)
{
	/*ULONG teb = *(ULONG *)((ULONG)ethread + 0xa8);
	ULONG limit = *(ULONG *)((ULONG)gdt + 0x38);
	DbgPrint("cpu %d, -> ethread %x, gdt38_limit %x\n", KeGetCurrentProcessorNumber(), ethread, limit);*/
}

PVOID __stdcall GetAllocStateAddress(ULONG va)
{
	PVOID  sValue = g_stateTable[va >> 12];
	if (sValue == (PVOID)ANALYSIS_STATE_INIT_VALUE)
	{
		PVOID allocVa = AllocateFromUserSpaceBufferEntries(va);
		sValue = (PVOID)((ULONG)allocVa - (va & 0xFFFFF000));
		g_stateTable[va >> 12] = sValue;
	}

	return (PVOID)(va + (ULONG)sValue);
}

ULONG __stdcall FaultCodeModifying(PVOID FaultAddr)
{
	ULONG vfn = (ULONG)FaultAddr >> 12;
	ULONG codePage = (ULONG)g_codeTable[vfn];

	for (ULONG k = 0; k < 0x1000; k++) 
	{
		ULONG codeBytesBase = *(ULONG *)(codePage + k * 4);
		if ((codeBytesBase >> 12) != vfn)
		{
			BLOCK_PROFILER *pBlockProfiler = (BLOCK_PROFILER *)*(ULONG *)(codeBytesBase + 5);
			if (pBlockProfiler)
			{
				if ((pBlockProfiler->CodeBytesPtr) && (pBlockProfiler->Flag == 0))
				{
					InterlockedExchange16((SHORT *)&pBlockProfiler->Flag, 1);
					//Patch -> mov [0FFFFAAAAh], eax
					InterlockedExchange8((CHAR *)codeBytesBase, 0xA3);
					*(UINT32 *)(codeBytesBase + 1) = LOG_ROLLBACK_FAULT_ADDR;
				}
			}
		}
	}

	ULONG   pte = 0xC0000000 + ((((ULONG)FaultAddr & 0xFFFFF000) >> 9) & 0x7ffff8);
	ULONG64 pa = *(ULONG64 *)pte;
	USHORT  origRights = *(USHORT *)((USHORT *)&g_pageState[(ULONG)FaultAddr >> 12] + 1);
	if (origRights & 0x1) 
	{
		*(ULONG64 *)pte = pa | 2LL;  //bit1 = 1, -> writable
		__invlpg((PVOID)FaultAddr);
		//byte1_written = 1
		InterlockedExchange8(((CHAR *)&g_pageState[vfn] + 1), 1);

		return 1;
	}
	else  //Handled by the system
	{
		UCHAR  nxBit = *((UCHAR *)&g_pageState[vfn] + 3);
		//*(ULONG64 *)pte = (pa & 0x7FFFFFFFFFFFFFFF) | (nxBit << 63);
		*(ULONG64 *)pte = (pa & 0x7FFFFFFFFFFFFFFF) | (1ULL << 63);
		__invlpg((PVOID)FaultAddr);

		MEMORY_BASIC_INFORMATION bi;
		NTSTATUS status = pZwQueryVirtualMemory(NtCurrentProcess(), FaultAddr, MemoryBasicInformation, &bi,
			sizeof(MEMORY_BASIC_INFORMATION), NULL);

		return 0;
	}
}

VOID __stdcall FaultStatePageOut(ULONG FaultAddr, PKPAGE_FAULT_FRAME pFaultFrame, THREAD_DATA *pThreadData)
{
	ULONG  insAddr = pFaultFrame->Eip;

	ULONG  cBase = 0;
	ULONG  nBase = FaultAddr;
	ULONG  cLen = 1, nLen = 1;
	ULONG  cStateBase, nStateBase;
	ULONG  rStateBase = pThreadData->Teb + REG_STATE_SLOT_OFFSET;

	//Special treatment for several cases
	if (*(UINT8 *)(insAddr) == 0x66)  //word
	{
		if ((*(UINT8 *)(insAddr + 2) & 7) == 1)
		{
			cBase = pFaultFrame->Ecx;
		}
		else if ((*(UINT8 *)(insAddr + 2) & 7) == 2)
		{
			cBase = pFaultFrame->Edx;
		}
		cStateBase = (ULONG)GetAllocStateAddress(cBase);
		nStateBase = (ULONG)GetAllocStateAddress(nBase);

		if (*(UINT16 *)(insAddr + 1) == 0x01C7)      //mov word ptr [ecx], 0  
		{
			*(UINT8 *)(cStateBase) = 0;
			*(UINT8 *)(nStateBase) = 0;
			pFaultFrame->Eip += 5;
		}
		else if (*(UINT16 *)(insAddr + 1) == 0x1109) //or [ecx], dx
		{
			*(UINT8 *)(cStateBase) |= *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4);
			*(UINT8 *)(nStateBase) |= *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + 1);
			pFaultFrame->Eip += 3;
		}
		else if (*(UINT16 *)(insAddr + 1) == 0x0289) //mov [edx], ax  
		{
			*(UINT8 *)(cStateBase) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4);
			*(UINT8 *)(nStateBase) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + 1);
			pFaultFrame->Eip += 3;
		}
		else if (*(UINT16 *)(insAddr + 1) == 0x1189) //mov [ecx], dx
		{
			*(UINT8 *)(cStateBase) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4);
			*(UINT8 *)(nStateBase) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + 1);
			pFaultFrame->Eip += 3;
		}
		else if (*(UINT16 *)(insAddr + 1) == 0x018B) //mov ax, [ecx]
		{
			*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4) = *(UINT8 *)(cStateBase);
			*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + 1) = *(UINT8 *)(nStateBase);
			pFaultFrame->Eip += 3;
		}
		else if (*(UINT16 *)(insAddr + 1) == 0x118B) //mov dx, [ecx]
		{
			*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4) = *(UINT8 *)(cStateBase);
			*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + 1) = *(UINT8 *)(nStateBase);
			pFaultFrame->Eip += 3;
		}	
		else
		{
			__debugbreak();
		}
	}
	else  //dword
	{
		if ((*(UINT8 *)(insAddr + 1) & 7) == 1)
		{
			cBase = pFaultFrame->Ecx;
		}
		else if ((*(UINT8 *)(insAddr + 1) & 7) == 2)
		{
			cBase = pFaultFrame->Edx;
		}
		cStateBase = (ULONG)GetAllocStateAddress(cBase);
		nStateBase = (ULONG)GetAllocStateAddress(nBase);
		cLen = nBase - cBase;
		nLen = 4 - cLen;

		if (*(UINT16 *)(insAddr) == 0x01C7)      //mov  dword ptr [ecx], 0  
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(cStateBase + k) = 0;
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(nStateBase + k) = 0;
			}
			pFaultFrame->Eip += 6;
		}
		else if (*(UINT16 *)(insAddr) == 0x018B) //mov  eax, [ecx]  
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + k) = *(UINT8 *)(cStateBase + k);
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + cLen + k) = *(UINT8 *)(nStateBase + k);
			}
			pFaultFrame->Eip += 2;
		}
		else if ((*(UINT16 *)(insAddr) == 0x118B) || (*(UINT16 *)(insAddr) == 0x128B)) //mov  edx, [ecx/edx]  
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + k) = *(UINT8 *)(cStateBase + k);
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + cLen + k) = *(UINT8 *)(nStateBase + k);
			}
			pFaultFrame->Eip += 2;
		}
		else if (*(UINT16 *)(insAddr) == 0x1109) //or  [ecx], edx
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(cStateBase + k) |= *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + k);
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(nStateBase + k) |= *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + cLen + k);
			}
			pFaultFrame->Eip += 2;
		}
		else if (*(UINT16 *)(insAddr) == 0x1189) //mov  [ecx], edx
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(cStateBase + k) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + k);
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(nStateBase + k) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EDX) * 4 + cLen + k);
			}
			pFaultFrame->Eip += 2;
		}
		else if (*(UINT16 *)(insAddr) == 0x0289) //mov  [edx], eax
		{
			for (ULONG k = 0; k < cLen; k++)
			{
				*(UINT8 *)(cStateBase + k) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + k);
			}
			for (ULONG k = 0; k < nLen; k++)
			{
				*(UINT8 *)(nStateBase + k) = *(UINT8 *)(rStateBase + (UD_R_EDI - UD_R_EAX) * 4 + cLen + k);
			}
			pFaultFrame->Eip += 2;
		}
		else
		{
			__debugbreak();
		}
	}
}

ULONG __stdcall TargetPageFault(PVOID FaultAddr, PKPAGE_FAULT_FRAME pFaultFrame)
{
	//Errorcode£¬0: present, 1: write, 2: user-mode, 3:RSVD, 4:ins fetch, 5:PK, 6: SGX
	
	PROCESSOR_DATA *processorData = g_processorList[KeGetCurrentProcessorNumber()];
	THREAD_DATA *pThreadData = GET_THREAD_DATA();

	if ((0x66280 + g_ntdll_base) == pFaultFrame->Eip) //[BUG] ntdll!RtlBackoff:
	{
		DbgPrint("%d [EXCEPTION] esp %08x, pTrapFrame %08x, ErrCode %x.\n", 
			pThreadData->Tid, pFaultFrame->HardwareEsp, pFaultFrame, pFaultFrame->ErrCode);
	}

	if (pFaultFrame->ErrCode == 0x14)     //present=0£¬write=0£¬user-mode=1£¬RSVD=0£¬ins fetch=1
	{
		ULONG pageState = (ULONG)g_pageState[pFaultFrame->Eip >> 12];
		if (!(pageState & 0x8))
		{
			g_pageState[pFaultFrame->Eip >> 12] |= 0x8; 
		}
		else
		{
			return 1;
		}
	}
	else if (pFaultFrame->ErrCode == 0x15)  //present=1£¬write=0£¬user-mode=1£¬RSVD=0£¬ins fetch=1
	{
		if ((0x66280 + g_ntdll_base) == pFaultFrame->Eip) //ntdll!RtlBackoff:
		{
			DbgPrint("%d [PROCESS] esp %08x, pTrapFrame %08x, ErrCode %x.\n",
				pThreadData->Tid, pFaultFrame->HardwareEsp, pFaultFrame, pFaultFrame->ErrCode);
		}
		processorData->Counter0++;

		//KiUserExceptionDispatcher
		if ((NTDLL_EXCEPTION_DISPATCHER_OFFSET + g_ntdll_base) == pFaultFrame->Eip)
		{
			DbgPrint("%d [KiUserExceptionDispatcher] esp %08x, pTrapFrame %08x.\n", pThreadData->Tid, pFaultFrame->HardwareEsp, pFaultFrame);
			//DEBUG
		}

		//Rewriting
		pFaultFrame->Eip = FaultCodePageRewritingBlock(processorData, pThreadData, pFaultFrame->Eip);

		return 1;
	}

	if (FaultAddr < (PVOID)KERNEL_SPACE_BASE_ADDR)
	{
		if (*(ULONG *)((ULONG *)&g_pageState[(ULONG)FaultAddr >> 12] + 1) == 0x11)  //GUARD_PAGE
		{
			processorData->Counter7++;
			FaultStatePageOut((ULONG)FaultAddr, pFaultFrame, pThreadData);

			return 1;
		}
		else if (*(ULONG *)((ULONG *)&g_pageState[(ULONG)FaultAddr >> 12] + 1) == 1)
		{
			//__debugbreak();
		}	
		else if (g_pageState[(ULONG)FaultAddr >> 12] & 1)  //executed
		{
			if ((pFaultFrame->ErrCode & 6) == 6) //present=1/0£¬write=1£¬user-mode=1
			{
				processorData->Counter4++;
				ULONG retVal = FaultCodeModifying(FaultAddr);

				return retVal;
			}	
		}
	}
	else
	{
		if (FaultAddr == (PVOID)LOG_ROLLBACK_FAULT_ADDR)
		{
			processorData->Counter5++;
			//Get profiler from code
			BLOCK_PROFILER *pBlockProfiler = (BLOCK_PROFILER *)*(ULONG *)(pFaultFrame->Eip + 5);
			pFaultFrame->Eip = FaultCodePageRewritingBlock(processorData, pThreadData, pBlockProfiler->FaultIp);
			return 1;
		}	
		else if ((FaultAddr >= (PVOID)ANALYSIS_CODE_FAULT_BASE) && 
			(FaultAddr < (PVOID)(ANALYSIS_CODE_FAULT_BASE + 0x80000))) //jmp code rewriting
		{
			pFaultFrame->Ecx = (pFaultFrame->Ecx << 12) + pFaultFrame->Edx;
			pFaultFrame->Eip = pFaultFrame->Eip + 3;
			return 1;
		}	
		else
		{
			processorData->Counter6++;

			//The analysis code is executed before the native instructions, and may trigger the page fault.
			ULONG  originAddr = (ULONG)FaultAddr - KERNEL_SPACE_BASE_ADDR;
			ULONG  stateAddr = (ULONG)GetAllocStateAddress(originAddr);

			if ((*(USHORT *)(pFaultFrame->Eip) == 0x0289) ||   //mov [edx], eax
				(*(USHORT *)(pFaultFrame->Eip) == 0x0288) ||   //mov [edx], al
				(*(USHORT *)(pFaultFrame->Eip) == 0x128B) ||   //mov edx, [edx]
				(*(USHORT *)(pFaultFrame->Eip + 1) == 0x0289)) //mov [edx],ax
			{
				pFaultFrame->Edx = stateAddr;
			}
			else
			{
				pFaultFrame->Ecx = stateAddr;
			}
			__invlpg(FaultAddr);
				
			return 1;
		}
	}

	return 0;
}

}
