#include <stddef.h>
#include <stdint.h>

#define INITIAL_VALUE 0x1111111111111111ULL

__attribute__((used, visibility("default")))
volatile uint64_t initialized_global = INITIAL_VALUE;

__attribute__((used, visibility("default")))
volatile uint64_t ifunc_result_slot = 0;

static long raw_write(int fd, const void *buffer, size_t length) {
    register long rax __asm__("rax") = 1;
    register long rdi __asm__("rdi") = fd;
    register const void *rsi __asm__("rsi") = buffer;
    register size_t rdx __asm__("rdx") = length;

    __asm__ volatile(
        "syscall"
        : "+a"(rax)
        : "D"(rdi), "S"(rsi), "d"(rdx)
        : "rcx", "r11", "memory"
    );
    return rax;
}

static size_t append_string(char *output, size_t offset, const char *text) {
    while (*text != '\0') {
        output[offset++] = *text++;
    }
    return offset;
}

static size_t append_hex_u64(char *output, size_t offset, uint64_t value) {
    static const char digits[] = "0123456789abcdef";

    output[offset++] = '0';
    output[offset++] = 'x';
    for (int shift = 60; shift >= 0; shift -= 4) {
        output[offset++] = digits[(value >> shift) & 0xf];
    }
    return offset;
}

/*
 * The injected STT_GNU_IFUNC symbol points here.  ld.so calls this function
 * while processing the crafted GLOB_DAT relocation, before _start runs.
 */
__attribute__((used, noinline, visibility("default")))
void *relocation_time_printer(void) {
    char line[160];
    size_t length = 0;

    length = append_string(
        line,
        length,
        "[AAC] Called by ld.so before the entry point; initialized_global = "
    );
    length = append_hex_u64(line, length, initialized_global);
    line[length++] = '\n';
    raw_write(1, line, length);

    return (void *)&relocation_time_printer;
}

int main(void) {
    static const char message[] =
        "[ENTRY] This is main(), running after the executable entry point.\n";
    raw_write(1, message, sizeof(message) - 1);
    return 0;
}
