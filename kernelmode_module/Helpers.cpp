#include "pch.h"
#include "Helpers.h"

void Helpers::Log(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, args);
    va_end(args);
}

void Helpers::ToLowerCase(UCHAR* str, size_t size)
{
    if (!str || size == 0) return;

    for (size_t i = 0; i < size; i++) {
        // If we hit a null terminator before size is reached, stop.
        if (str[i] == '\0') break;

        // Check if character is Uppercase ASCII (A-Z)
        if (str[i] >= 'A' && str[i] <= 'Z') {
            // Convert to Lowercase by adding 32 (0x20)
            str[i] += 32;
        }
    }
}
