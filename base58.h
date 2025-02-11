#include <vector>
#include <string>
#include <cassert>

using namespace std;

const char pszBase58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

string EncodeBase58(const vector<unsigned char>& input) {
    // 计算前导零的数量
    int zeroes = 0;
    const int input_size = input.size();
    while (zeroes < input_size && input[zeroes] == 0) {
        ++zeroes;
    }

    // 计算足够的空间
    const int data_size = input_size - zeroes;
    const int size = data_size * 138 / 100 + 1; // log(256)/log(58) ≈ 138/100
    vector<unsigned char> b58(size, 0); // 初始化为全0

    int length = 0; // 当前b58数组的有效长度

    // 处理每一个字节
    for (int idx = zeroes; idx < input_size; ++idx) {
        int carry = input[idx];
        int i = 0;
        int j = size - 1;

        // 处理b58数组，从后往前
        while (j >= 0 && (carry != 0 || i < length)) {
            carry += 256 * b58[j];
            b58[j] = carry % 58;
            carry /= 58;
            --j;
            ++i;
        }

        assert(carry == 0);
        length = i; // 更新有效长度
    }

    // 跳过前导零
    auto it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0) {
        ++it;
    }

    // 构建结果字符串
    string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1'); // 前导零转换为'1'

    for (; it != b58.end(); ++it) {
        str += pszBase58[*it];
    }

    return str;
}