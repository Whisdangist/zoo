#include <vector>
#include <string>
#include <algorithm>
#include <cassert>

using namespace std;

const char pszBase58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const int mapBase58[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};


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

vector<unsigned char> DecodeBase58(const string& input) {
    // 跳过前导的'1'（Base58中的零）
    int zeroes = 0;
    while (zeroes < input.size() && input[zeroes] == '1') {
        ++zeroes;
    }

    // 将Base58字符转换为对应的数值
    vector<unsigned char> indices;
    for (char c : input) {
        if (mapBase58[static_cast<unsigned char>(c)] == -1) {
            return {}; // 非法字符
        }
        indices.push_back(mapBase58[static_cast<unsigned char>(c)]);
    }

    // 计算足够的空间
    const int size = indices.size() * 733 / 1000 + 1; // log(58)/log(256) ≈ 733/1000
    vector<unsigned char> result(size, 0);

    int length = 0; // 当前result数组的有效长度

    // 处理每一个Base58字符
    for (int idx = 0; idx < indices.size(); ++idx) {
        int carry = indices[idx];
        int i = 0;
        int j = size - 1;

        // 将result * 58 + 当前字符值
        while (j >= 0 && (carry != 0 || i < length)) {
            carry += 58 * result[j];
            result[j] = carry % 256;
            carry /= 256;
            --j;
            ++i;
        }

        assert(carry == 0);
        length = i; // 更新有效长度
    }

    // 跳过前导零
    auto it = result.begin() + (size - length);
    while (it != result.end() && *it == 0) {
        ++it;
    }

    // 构建最终结果，包括前导零
    vector<unsigned char> decoded;
    decoded.reserve(zeroes + (result.end() - it));
    decoded.assign(zeroes, 0); // 前导零
    decoded.insert(decoded.end(), it, result.end());

    return decoded;
}