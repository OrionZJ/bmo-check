#include <stddef.h>
#include <stdint.h>

uint8_t rep_source[64];
uint8_t rep_target[64];

int main(void) {
    for (size_t index = 0; index < sizeof(rep_source); ++index)
        rep_source[index] = (uint8_t)(index + 1);
    const uint8_t *source = rep_source;
    uint8_t *target = rep_target;
    size_t count = sizeof(rep_source);
    __asm__ volatile("cld\n\trep movsb"
                     : "+S"(source), "+D"(target), "+c"(count)
                     :
                     : "memory");
    for (size_t index = 0; index < sizeof(rep_target); ++index) {
        if (rep_target[index] != (uint8_t)(index + 1))
            return 1;
    }
    return 0;
}
