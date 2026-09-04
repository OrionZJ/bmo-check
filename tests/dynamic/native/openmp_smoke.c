#include <omp.h>

int main(void) {
    int sum = 0;
#pragma omp parallel for num_threads(2) reduction(+ : sum)
    for (int index = 0; index < 100; ++index)
        sum += index;
    return sum == 4950 ? 0 : 1;
}
