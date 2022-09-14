#pragma once
#include "types.h"
extern "C" {
    unsigned char __stdcall AsmInvept(
        _In_ InvEptType invept_type,
        _In_ const InvEptDescriptor* invept_descriptor);
}