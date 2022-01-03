#pragma once
#include "types.h"


enum class VmxStatus : unsigned __int8 {
	kOk = 0,                  //!< Operation succeeded
	kErrorWithStatus = 1,     //!< Operation failed with extended status available
	kErrorWithoutStatus = 2,  //!< Operation failed without status available
};

#define PAGE_SIZE 0x1000
#define PAGE_SIZE2M PAGE_SIZE * 512
#define PAGE_ALIGN(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define PAGE_ALIGN2M(Va) ((PVOID)((ULONG_PTR)(Va) & ~(PAGE_SIZE2M - 1)))
// Contains a single steal hook information
typedef struct HookInformation {
	void* patch_address;  // An address where a hook is installed
	// Physical address of the above two copied pages
	ULONG64 pa_base_for_rw;
	ULONG64 pa_base_for_exec;
	bool isEnable;
}HookInformation, * PHookInformation;

// Data structure shared across all processors
typedef struct SharedShadowHookData {
	HookInformation hooks[MAX_HOOKS];  // Hold installed hooks
}SharedShadowHookData, *PSharedShadowHookData;

typedef struct ShadowPte
{
	ULONG64 pa_base_for_2m; //保存这个页表对应的2M页
	ept_pte shadowPte[512];
}ShadowPte,*PShadowPte;

//
// EPT entry and common fields
//
VmxStatus UtilInveptGlobal(ept_pointer eptPoint);
NTSTATUS VoyagerEptAddFakePage(u64 uHookAddr, u64 uPageRead, u64 uPageExec);
NTSTATUS VoyagerEptDelteFakePage(u64 uHookAddr);
bool VoyagerHandleEptViolation(EptViolationQualification* eptQualification,void* fault_va);
void changeEPTAttribute(ept_pointer eptp, guest_phys_t guest_pa, bool bCanExecute);
void disablePageProtection(ept_pointer eptp, guest_phys_t guest_pa);
void split_2mb_to_4kb(ept_pointer eptp, guest_phys_t guest_pa, host_phys_t host_pa);
void merge_4kb_to_2mb(ept_pointer eptp, guest_phys_t guest_pa, host_phys_t host_pa);
bool map_4k(ept_pointer eptp,guest_phys_t guest_pa, guest_phys_t host_pa);
HookInformation* ShpFindPatchInfoByPage(SharedShadowHookData* shared_sh_data, void* address);
HookInformation* ShpFindPatchInfoBy2MPage(SharedShadowHookData* shared_sh_data, void* address);
HookInformation* ShpFindPatchInfoByAddress(SharedShadowHookData* shared_sh_data, void* address);