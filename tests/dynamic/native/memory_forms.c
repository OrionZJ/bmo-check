#include <stdint.h>

double fp_source = 3.25;
double fp_target;
uint8_t vector_source[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                             9, 10, 11, 12, 13, 14, 15, 16};
uint8_t vector_target[16];

__asm__(
    ".text\n"
    ".globl bmo_callee\n"
    "bmo_callee:\n"
    ".globl bmo_ret_site\n"
    "bmo_ret_site:\n"
    "ret\n");

extern void bmo_callee(void);

int main(void) {
    __asm__ volatile(
        ".globl bmo_push_site\n"
        "bmo_push_site:\n\t"
        "push %%rax\n\t"
        ".globl bmo_pop_site\n"
        "bmo_pop_site:\n\t"
        "pop %%rax\n\t"
        ".globl bmo_call_site\n"
        "bmo_call_site:\n\t"
        "call bmo_callee\n\t"
        ".globl bmo_fld_site\n"
        "bmo_fld_site:\n\t"
        "fldl fp_source(%%rip)\n\t"
        ".globl bmo_fst_site\n"
        "bmo_fst_site:\n\t"
        "fstpl fp_target(%%rip)\n\t"
        ".globl bmo_vector_load_site\n"
        "bmo_vector_load_site:\n\t"
        "movdqu vector_source(%%rip), %%xmm0\n\t"
        ".globl bmo_vector_store_site\n"
        "bmo_vector_store_site:\n\t"
        "movdqu %%xmm0, vector_target(%%rip)\n\t"
        :
        :
        : "rax", "xmm0", "memory");
    if (fp_target != fp_source)
        return 1;
    for (int index = 0; index < 16; ++index) {
        if (vector_target[index] != vector_source[index])
            return 2;
    }
    return 0;
}
