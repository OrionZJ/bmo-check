#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    void *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    ((volatile int *)mapping)[0] = 1;
    return munmap(mapping, 4096) == 0 ? 0 : 3;
}
