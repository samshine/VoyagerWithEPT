#pragma once
#include <intrin.h>
#include <xmmintrin.h>
#include <cstddef>

#include <Windows.h>
#include <ntstatus.h>
#include "ia32.hpp"

#define MAX_HOOKS 4 //最多几个hook

#define VMEXIT_KEY 0xDEADBEEFDEADBEEF
#define VMEXIT_ADDPAGE 0xEEEEEEEABCEEEEEE
#define VMEXIT_DELETEPAGE 0xEEEEEEEABCEEEEEF
#define PAGE_4KB 0x1000
#define PAGE_2MB PAGE_4KB * 512
#define PAGE_1GB PAGE_2MB * 512

using u8 = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;
using u128 = __m128;

using guest_virt_t = u64;
using guest_phys_t = u64;
using host_virt_t = u64;
using host_phys_t = u64;

enum class vmexit_command_t
{
	init_page_tables,
	read_guest_phys,
	write_guest_phys,
	copy_guest_virt,
	get_dirbase,
	translate,
	add_shadow_page,
	add_shadow_page_phys,
	delete_shadow_page,
	unhide_shadow_page,
	disable_page_protection,
	DiablePCID
};

enum class vmxroot_error_t
{
	error_success,
	pml4e_not_present,
	pdpte_not_present,
	pde_not_present,
	pte_not_present,
	vmxroot_translate_failure,
	invalid_self_ref_pml4e,
	invalid_mapping_pml4e,
	invalid_host_virtual,
	invalid_guest_physical,
	invalid_guest_virtual,
	page_table_init_failed
};

typedef union _command_t
{
	struct _copy_phys
	{
		host_phys_t  phys_addr;
		guest_virt_t buffer;
		u64 size;
	} copy_phys;

	struct _copy_virt
	{
		guest_phys_t dirbase_src;
		guest_virt_t virt_src;
		guest_phys_t dirbase_dest;
		guest_virt_t virt_dest;
		u64 size;
	} copy_virt;

	struct _translate_virt
	{
		guest_virt_t virt_src;
		guest_phys_t phys_addr;
	} translate_virt;

	struct _addShadowPage
	{
		guest_virt_t uVirtualAddrToHook;
		guest_virt_t uPageRead;
		guest_virt_t uPageExecute;
	}addShadowPage;

	struct _addShadowPagePhys
	{
		guest_virt_t uVirtualAddrToHook;
		guest_phys_t uPageRead;
		guest_phys_t uPageExecute;

	}addShadowPagePhys;

	struct _deleteShaowPage
	{
		guest_virt_t uVirtualAddrToHook;
	}deleteShaowPage;

	struct _unHideShaowPage
	{
		guest_virt_t uVirtualAddrToHook;
	}unHideShaowPage;

	struct _disablePageProtection
	{
		guest_phys_t phys_addr;
	}disablePageProtection;

	guest_phys_t dirbase;

} command_t, * pcommand_t;

typedef struct _context_t
{
	u64 rax;
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 rsp;
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u128 xmm0;
	u128 xmm1;
	u128 xmm2;
	u128 xmm3;
	u128 xmm4;
	u128 xmm5;
} context_t, *pcontext_t;

#if WINVER > 1803
using vmexit_handler_t = void (__fastcall*)(pcontext_t* context, void* unknown);
#else
using vmexit_handler_t = void(__fastcall*)(pcontext_t context, void* unknown);
#endif

#pragma pack(push, 1)
typedef struct _voyager_t
{
	u64 vmexit_handler_rva;
	u64 hyperv_module_base;
	u64 hyperv_module_size;
	u64 payload_base;
	u64 payload_size;
} voyager_t, *pvoyager_t;
#pragma pack(pop)

__declspec(dllexport) inline voyager_t voyager_context;

union EptViolationQualification {
	ULONG64 all;
	struct {
		ULONG64 read_access : 1;                   //!< [0]
		ULONG64 write_access : 1;                  //!< [1]
		ULONG64 execute_access : 1;                //!< [2]
		ULONG64 ept_readable : 1;                  //!< [3]
		ULONG64 ept_writeable : 1;                 //!< [4]
		ULONG64 ept_executable : 1;                //!< [5]
		ULONG64 ept_executable_for_user_mode : 1;  //!< [6]
		ULONG64 valid_guest_linear_address : 1;    //!< [7]
		ULONG64 caused_by_translation : 1;         //!< [8]
		ULONG64 user_mode_linear_address : 1;      //!< [9]
		ULONG64 readable_writable_page : 1;        //!< [10]
		ULONG64 execute_disable_page : 1;          //!< [11]
		ULONG64 nmi_unblocking : 1;                //!< [12]
	} fields;
};

enum class InvEptType : ULONG_PTR {
	kSingleContextInvalidation = 1,
	kGlobalInvalidation = 2,
};

union EptPointer {
	ULONG64 all;
	struct {
		ULONG64 memory_type : 3;                      //!< [0:2]
		ULONG64 page_walk_length : 3;                 //!< [3:5]
		ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
		ULONG64 reserved1 : 5;                        //!< [7:11]
		ULONG64 pml4_address : 36;                    //!< [12:48-1]
		ULONG64 reserved2 : 16;                       //!< [48:63]
	} fields;
};

struct InvEptDescriptor {
	ULONG64 ept_pointer;
	ULONG64 reserved1;
};