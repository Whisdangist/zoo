#include <vector>
#include <cstdint>
#include <algorithm>
#include <iostream>

// Keccak 常量
constexpr size_t KECCAK_ROUNDS = 24;
constexpr size_t KECCAK_STATE_SIZE = 1600 / 8; // 1600 bits = 200 bytes
constexpr size_t KECCAK_HASH_SIZE = 32;        // 256 bits = 32 bytes

// Keccak 轮常数
constexpr uint64_t RC[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// 循环左移宏
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// Keccak 置换函数
void keccakf(uint64_t state[25]) {
    for (size_t round = 0; round < KECCAK_ROUNDS; ++round) {
        // Theta 步骤
        uint64_t C[5], D[5];
        for (size_t i = 0; i < 5; ++i) {
            C[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (size_t i = 0; i < 5; ++i) {
            D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
        }
        for (size_t i = 0; i < 25; i += 5) {
            for (size_t j = 0; j < 5; ++j) {
                state[i + j] ^= D[j];
            }
        }

        // Rho 和 Pi 步骤
        uint64_t temp = state[1];
        size_t x = 1, y = 0;
        for (size_t t = 0; t < 24; ++t) {
            const size_t X = x;
            const size_t Y = y;
            x = Y;
            y = (2 * X + 3 * Y) % 5;
            const size_t index = x + 5 * y;
            const uint64_t next = state[index];
            state[index] = ROTL64(temp, ((t + 1) * (t + 2) / 2) % 64);
            temp = next;
        }

        // Chi 步骤
        for (size_t i = 0; i < 25; i += 5) {
            uint64_t temp[5];
            for (size_t j = 0; j < 5; ++j) {
                temp[j] = state[i + j];
            }
            for (size_t j = 0; j < 5; ++j) {
                state[i + j] = temp[j] ^ (~temp[(j + 1) % 5] & temp[(j + 2) % 5]);
            }
        }

        // Iota 步骤
        state[0] ^= RC[round];
    }
}

// Keccak-256 哈希函数
std::vector<uint8_t> keccak256(const std::vector<uint8_t>& data) {
    uint64_t state[25] = {0}; // 初始化为全0
    const size_t block_size = 136; // 块大小：1088 bits = 136 bytes

    // 吸收阶段
    size_t offset = 0;
    while (offset < data.size()) {
        const size_t len = std::min(block_size, data.size() - offset);
        for (size_t i = 0; i < len; ++i) {
            const size_t word = (i / 8);
            const size_t shift = (i % 8) * 8;
            state[word] ^= static_cast<uint64_t>(data[offset + i]) << shift;
        }
        offset += len;
        if (len == block_size) {
            keccakf(state);
        }
    }

    // Keccak 填充规则：0x01 + 0x00... + 0x80
    const size_t remaining = data.size() % block_size;
    const size_t pad_start = remaining;
    const size_t pad_len = block_size - remaining;

    // 填充第一个字节：0x01
    state[pad_start / 8] ^= static_cast<uint64_t>(0x01) << ((pad_start % 8) * 8);

    // 填充最后一个字节：0x80
    const size_t last_byte_pos = pad_start + pad_len - 1;
    state[last_byte_pos / 8] ^= static_cast<uint64_t>(0x80) << ((last_byte_pos % 8) * 8);

    // 执行最终的置换
    keccakf(state);

    // 提取哈希值（前32字节）
    std::vector<uint8_t> hash(KECCAK_HASH_SIZE);
    for (size_t i = 0; i < KECCAK_HASH_SIZE; ++i) {
        const size_t word = i / 8;
        const size_t shift = (i % 8) * 8;
        hash[i] = static_cast<uint8_t>((state[word] >> shift) & 0xFF);
    }
    return hash;
}
