//#include "ept.h"
#include "vmexit.h"

typedef LARGE_INTEGER PHYSICAL_ADDRESS, * PPHYSICAL_ADDRESS;

#define EPT_PD_MASK                         (~((ULONG64)(0x200000 - 1)))


#if WINVER > 1803
void vmexit_handler(pcontext_t* context, void* unknown)
#else
void vmexit_handler(pcontext_t context, void* unknown)
#endif
{

#if WINVER > 1803
	pcontext_t guest_registers = *context;
#else
	pcontext_t guest_registers = context;
#endif

	size_t vmexit_reason;
	__vmx_vmread(VMCS_EXIT_REASON, &vmexit_reason);
	if (vmexit_reason == VMX_EXIT_REASON_EXECUTE_CPUID)
	{
		if (guest_registers->rcx == VMEXIT_KEY)
		{
			switch ((vmexit_command_t)guest_registers->rdx)
			{
				case vmexit_command_t::init_page_tables:
				{
					dbg::print("init_page_tables:\n");
					guest_registers->rax = (u64)mm::init();
					break;
				}
				case vmexit_command_t::get_dirbase:
				{
					//dbg::print("get_dirbase\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);

					// cr3 can contain other high bits so just to be safe
					// get the pfn and bitshift it...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;
					command_data.dirbase = guest_dirbase;
					guest_registers->rax = (u64)vmxroot_error_t::error_success;

					vmexit::set_command(
						guest_registers->r8, command_data);
					break;
				}
				case vmexit_command_t::read_guest_phys:
				{
					//dbg::print("read_guest_phys\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
					// from 1809-1909 PCIDE is enabled in CR4 and so cr3 contains some other stuff...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					guest_registers->rax =
						(u64)mm::read_guest_phys(
							guest_dirbase,
							command_data.copy_phys.phys_addr,
							command_data.copy_phys.buffer,
							command_data.copy_phys.size);

					vmexit::set_command(
						guest_registers->r8, command_data);
					break;
				}
				case vmexit_command_t::write_guest_phys:
				{
					//dbg::print("write_guest_phys\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
					// from 1809-1909 PCIDE is enabled in CR4 and so cr3 contains some other stuff...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					guest_registers->rax =
						(u64)mm::write_guest_phys(
							guest_dirbase,
							command_data.copy_phys.phys_addr,
							command_data.copy_phys.buffer,
							command_data.copy_phys.size);

					vmexit::set_command(
						guest_registers->r8, command_data);
					break;
				}
				case vmexit_command_t::copy_guest_virt:
				{
					//dbg::print("copy_guest_virt\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					auto virt_data = command_data.copy_virt;
					guest_registers->rax =
						(u64)mm::copy_guest_virt(
							virt_data.dirbase_src,
							virt_data.virt_src,
							virt_data.dirbase_dest,
							virt_data.virt_dest,
							virt_data.size);
					break;
				}
				case vmexit_command_t::translate:
				{
					//dbg::print("translate\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					command_data.translate_virt.phys_addr =
						mm::translate_guest_virtual(guest_dirbase,
							command_data.translate_virt.virt_src);

					guest_registers->rax =
						(u64)vmxroot_error_t::error_success;

					vmexit::set_command(
						guest_registers->r8, command_data);
					break;
				}
				case vmexit_command_t::add_shadow_page:
				{
					dbg::print("add_shadow_page\n");
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);

					// cr3 can contain other high bits so just to be safe
					// get the pfn and bitshift it...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					cpuid_eax_01 cpuid_value;
					__cpuid((int*)&cpuid_value, 1);
					UINT32_t uProcessorNum = cpuid_value.cpuid_additional_information.initial_apic_id;

					guest_virt_t uAddr = command_data.addShadowPage.uVirtualAddrToHook;
					guest_virt_t virtualRead = command_data.addShadowPage.uPageRead;
					guest_virt_t virtualExecute = command_data.addShadowPage.uPageExecute;
					dbg::print("ProcessorNum:%d,uAddr:%llx,virtualRead:%llx,virtualExecute:%llx\n", uProcessorNum, uAddr, virtualRead, virtualExecute);
					guest_phys_t uPageRead = mm::translate_guest_virtual(guest_dirbase, virtualRead, mm::map_type_t::map_src); //save the page for read
					guest_phys_t uPageExec = mm::translate_guest_virtual(guest_dirbase, virtualExecute, mm::map_type_t::map_src); //save the page for exec
					dbg::print("ReadPhysical:%llx,ExecPhysical:%llx\n", uPageRead,uPageExec);
					ept_pointer eptp;
					mm::phys_addr_t guest_phys{ uPageExec };
					__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
					VoyagerEptAddFakePage(uAddr, uPageRead, uPageExec); //record hook information
					split_2mb_to_4kb(eptp, uPageExec& EPT_PD_MASK, uPageExec& EPT_PD_MASK);
					//it's all 4k page now
					changeEPTAttribute(eptp, uPageExec, true);//set the page attribute to exec only
					break;
				}
				case vmexit_command_t::add_shadow_page_phys:
				{
					auto command_data =
						vmexit::get_command(guest_registers->r8);

					guest_virt_t uAddr = command_data.addShadowPagePhys.uVirtualAddrToHook;
				
					guest_phys_t uPageRead = command_data.addShadowPagePhys.uPageRead; //save the page for read
					guest_phys_t uPageExec = command_data.addShadowPagePhys.uPageExecute; //save the page for exec
					dbg::print("ReadPhysical:%llx,ExecPhysical:%llx\n", uPageRead, uPageExec);
					ept_pointer eptp;
					mm::phys_addr_t guest_phys{ uPageExec };
					__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
					VoyagerEptAddFakePage(uAddr, uPageRead, uPageExec); //record hook information
					split_2mb_to_4kb(eptp, uPageExec&EPT_PD_MASK, uPageExec&EPT_PD_MASK);
					//it's all 4k page now
					changeEPTAttribute(eptp, uPageExec, true);//set the page attribute to exec only
					break;
				}
				case vmexit_command_t::delete_shadow_page:
				{
					dbg::print("delete_shadow_page\n");
					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
					auto command_data =
						vmexit::get_command(guest_registers->r8);
					// cr3 can contain other high bits so just to be safe
					// get the pfn and bitshift it...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					u64 uAddr = command_data.deleteShaowPage.uVirtualAddrToHook; //begin to search for the page
					dbg::print("delete addr:%llx\n", uAddr);
				
					PSharedShadowHookData pShadowHook = (PSharedShadowHookData)&mm::ShadowHookData;
					PHookInformation pInfo = NULL;
					pInfo = ShpFindPatchInfoByAddress(pShadowHook, (void*)uAddr);
					if (!pInfo)
					{
						break;
					}
					ept_pointer eptp;
					__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
					u64 uPhyExe = pInfo->pa_base_for_exec;
					u64 uPhyRW = pInfo->pa_base_for_rw;
					map_4k(eptp, uPhyExe, uPhyExe); //remap to the exec page,and set page attribute to R/W only
					VoyagerEptDelteFakePage(uAddr); //delete
					pInfo = ShpFindPatchInfoBy2MPage((PSharedShadowHookData)&mm::ShadowHookData, (void*)uAddr);
					if (!pInfo) //if no other hook information in 2M,then delete the resource
					{
						dbg::print("merge_4kb_to_2mb\n");
						merge_4kb_to_2mb(eptp, uPhyExe & EPT_PD_MASK, uPhyExe & EPT_PD_MASK);
					}
					break;
				}
				case vmexit_command_t::unhide_shadow_page:
				{
					dbg::print("unhide_shadow_page\n");
					u64 guest_dirbase;
					__vmx_vmread(VMCS_GUEST_CR3, &guest_dirbase);
					auto command_data =
						vmexit::get_command(guest_registers->r8);
					// cr3 can contain other high bits so just to be safe
					// get the pfn and bitshift it...
					guest_dirbase = cr3{ guest_dirbase }.pml4_pfn << 12;

					u64 uAddr = command_data.unHideShaowPage.uVirtualAddrToHook; //begin to search for the page
					dbg::print("unHide addr:%llx\n", uAddr);
					
					PSharedShadowHookData pShadowHook = (PSharedShadowHookData)&mm::ShadowHookData;
					PHookInformation pInfo = NULL;
					pInfo = ShpFindPatchInfoByAddress(pShadowHook, (void*)uAddr);
					if (!pInfo)
					{
						break;
					}
					ept_pointer eptp;
					__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
					u64 uPhyExe = pInfo->pa_base_for_exec;
					u64 uPhyRW = pInfo->pa_base_for_rw;
					map_4k(eptp, uPhyExe, uPhyExe); //remap to exec,and set page attribute to RWE
					break;
				}
				case vmexit_command_t::disable_page_protection:
				{
					auto command_data =
						vmexit::get_command(guest_registers->r8);
					guest_phys_t uPagePhyAddr = command_data.disablePageProtection.phys_addr;
					ept_pointer eptp;
					__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
					disablePageProtection(eptp, uPagePhyAddr);
					break;
				}
				default:
					break;
			}
			// advance instruction pointer...
			size_t rip, exec_len;
			__vmx_vmread(VMCS_GUEST_RIP, &rip);
			__vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &exec_len);
			__vmx_vmwrite(VMCS_GUEST_RIP, rip + exec_len);
			return;
		}
	}
	else if (vmexit_reason == VMX_EXIT_REASON_EPT_VIOLATION)
	{
		//dbg::print("[EPT Violation]\n");
		EptViolationQualification exit_qualification;
		__vmx_vmread(VMCS_EXIT_QUALIFICATION, (size_t*)&exit_qualification);
		u64 fault_pa = 0, fault_va = 0;
		__vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, (size_t*)&fault_pa);
		if (exit_qualification.fields.valid_guest_linear_address)
		{
			__vmx_vmread(VMCS_EXIT_GUEST_LINEAR_ADDRESS, (size_t*)&fault_va);
		}
		else
		{
			fault_va = 0;
		}
		
		if (exit_qualification.fields.ept_readable ||
			exit_qualification.fields.ept_writeable ||
			exit_qualification.fields.ept_executable) 
		{
			dbg::print("[EPT Violation] fault_va:%llx,fault_pa:%llx\n", fault_va, fault_pa);
			ept_pointer eptp;

			__vmx_vmread(VMCS_CTRL_EPT_POINTER, (size_t*)&eptp);
			// EPT entry is present. Permission violation.
			if (exit_qualification.fields.caused_by_translation) 
			{
				bool isHandled = VoyagerHandleEptViolation(&exit_qualification,(void*)fault_va);//replace
				if (isHandled)
				{
					dbg::print("Ept Violation have handled\n");
					UtilInveptGlobal(eptp);
					return;
				}
			}
			
		}
	}

	// call original vmexit handler...
	reinterpret_cast<vmexit_handler_t>(
		reinterpret_cast<u64>(&vmexit_handler) -
			voyager_context.vmexit_handler_rva)(context, unknown);
}