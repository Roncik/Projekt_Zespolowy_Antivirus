// PRECOMPILED HEADER FILE
#pragma once

#include <ntddk.h>
#include <ntimage.h>
#include <aux_klib.h>
#include <ntstrsafe.h>


#if defined(UNICODE)
# define RtlStringCbPrintf RtlStringCbPrintfA
#else
# define RtlStringCbPrintf RtlStringCbPrintfW
#endif