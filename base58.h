#include <bits/stdc++.h>
using namespace std;

// Base58 字符集
const char pszBase58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Base58 编码函数
string EncodeBase58(const vector<unsigned char>& input)
{
    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    vector<unsigned char> data = input;

    // 计算前导零字节数
    while (data.size() > 0 && data[0] == 0) {
        data.erase(data.begin());  // 去除首个元素
        zeroes++;
    }

    // 计算足够的空间进行 Base58 表示
    int size = data.size() * 138 / 100 + 1; // log(256) / log(58), 向上取整
    vector<unsigned char> b58(size);

    // 处理字节数据
    while (data.size() > 0) {
        int carry = data[0];
        int i = 0;
        
        // 将 b58 * 256 + 当前字节
        for (auto it = b58.rbegin(); (carry != 0 || i < length) && it != b58.rend(); ++it, ++i) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        data.erase(data.begin());  // 移除第一个元素
    }

    // 跳过 Base58 结果中的前导零字节
    auto it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        ++it;

    // 将结果转化为字符串
    string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');  // 前导零用 '1' 来表示

    // 将 Base58 数字转化为字符
    while (it != b58.end()) {
        str += pszBase58[*(it++)];
    }

    return str;
}
