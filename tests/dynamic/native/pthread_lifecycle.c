#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int shared_value;
static uint64_t atomic_word;
static volatile sig_atomic_t signal_seen;

static void signal_handler(int number) {
    signal_seen = number;
}

static void *worker(void *unused) {
    (void)unused;
    pthread_mutex_lock(&lock);
    shared_value += 1;
    pthread_mutex_unlock(&lock);
    return NULL;
}

int main(void) {
    signal(SIGUSR1, signal_handler);
    raise(SIGUSR1);
    if (signal_seen != SIGUSR1)
        return 1;
    void *library = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (library == NULL || dlsym(library, "cos") == NULL)
        return 9;

    __asm__ volatile("lfence\n\tsfence\n\tmfence" ::: "memory");
    __atomic_fetch_add(&atomic_word, 1, __ATOMIC_SEQ_CST);
    uint64_t exchange = 2;
    __asm__ volatile("xchgq %0, %1"
                     : "+r"(exchange), "+m"(atomic_word)
                     :
                     : "memory");

    volatile unsigned char *heap = malloc(32);
    if (heap == NULL)
        return 2;
    heap[0] = 1;
    heap = realloc((void *)heap, 64);
    if (heap == NULL)
        return 3;
    heap[63] = 2;

    volatile unsigned char *mapping = mmap(
        NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 4;
    mapping[0] = 3;

    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0)
        return 5;
    if (pthread_join(thread, NULL) != 0)
        return 6;

    free((void *)heap);
    if (munmap((void *)mapping, 4096) != 0)
        return 7;
    dlclose(library);
    return shared_value == 1 ? 0 : 8;
}
