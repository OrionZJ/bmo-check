#include <immintrin.h>
#include <stdint.h>

int32_t gather_source[64];
volatile int32_t gather_sink[8];

int main(void) {
    static const int32_t offsets[8] = {0, 3, 7, 12, 18, 25, 33, 42};
    for (int index = 0; index < 64; ++index)
        gather_source[index] = index * 17 + 5;
    const __m256i indices = _mm256_loadu_si256((const __m256i *)offsets);
    const __m256i values = _mm256_i32gather_epi32(gather_source, indices, 4);
    _mm256_storeu_si256((__m256i *)(void *)gather_sink, values);
    for (int index = 0; index < 8; ++index) {
        // 验证时不再读 source，否则追踪测试可能把这些普通 load
        // 误当成 gather 已经记录完整。
        if (gather_sink[index] != offsets[index] * 17 + 5)
            return 1;
    }
    return 0;
}
