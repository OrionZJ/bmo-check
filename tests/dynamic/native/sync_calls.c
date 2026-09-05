#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>

int main(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_barrier_t barrier;
    sem_t semaphore;
    struct timespec expired = {0, 0};
    if (sem_init(&semaphore, 0, 0) || pthread_barrier_init(&barrier, NULL, 1))
        return 1;
    if (sem_trywait(&semaphore) != -1 || errno != EAGAIN)
        return 2;
    if (sem_timedwait(&semaphore, &expired) != -1 || errno != ETIMEDOUT)
        return 3;
    if (sem_post(&semaphore) || sem_wait(&semaphore))
        return 4;
    if (pthread_barrier_wait(&barrier) != PTHREAD_BARRIER_SERIAL_THREAD)
        return 5;
    pthread_mutex_lock(&mutex);
    if (pthread_cond_timedwait(&cond, &mutex, &expired) != ETIMEDOUT)
        return 6;
    pthread_mutex_unlock(&mutex);
    if (pthread_cond_signal(&cond) || pthread_cond_broadcast(&cond))
        return 7;
    sem_destroy(&semaphore);
    pthread_barrier_destroy(&barrier);
    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&mutex);
    return 0;
}
