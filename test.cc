#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include "keccak256.h"
using namespace std;

vector<string> get_wordlist() {
    vector<string> BIP39_WORDLIST;
    ifstream file("bip39_words.txt");
    
    if (file.is_open()) {
        string word;
        while (getline(file, word)) {
            // 去掉每个单词的前后空白字符
            size_t first = word.find_first_not_of(" \t\r\n");
            size_t last = word.find_last_not_of(" \t\r\n");
            word = word.substr(first, last - first + 1);
            BIP39_WORDLIST.push_back(word);
        }
        file.close();
    } else {
        cerr << "无法打开文件!" << endl;
    }

    return BIP39_WORDLIST;
}

const vector<string> BIP39_WORDLIST = get_wordlist();
const string pre_words_str = "dentist gauge whisper cattle lemon pink benefit ship subject state";
const string target_address = "TEyy2fr2xMYwwsZUxmNx7HD4LT9WhEorPP";


vector<unsigned char> int2bytes(__uint128_t entropy) {
    vector<unsigned char> output(16);
    for (int i = 0; i < 16; ++i) {
        output[15 - i] = static_cast<unsigned char>((entropy >> (i * 8)) & 0xFF);
    }
    return output;
}

vector<unsigned char> sha256(const vector<unsigned char> &data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, data.data(), data.size());
    // SHA256_Final(hash, &sha256);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

struct EVP_MD_CTX_t {
    const EVP_MD *digest;
    ENGINE *engine;
    unsigned long flags;
    void *md_data;
    EVP_PKEY_CTX *pctx;
    int(*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
};

struct KECCAK1600_CTX {
    uint64_t A[5][5];
    size_t block_size;
    size_t md_size;
    size_t num;
    unsigned char buf[1600 / 8 - 32];
    unsigned char pad;
};

// // 计算 Keccak-256 哈希
// vector<unsigned char> keccak256(const vector<unsigned char>& data) {
//     vector<unsigned char> hash(EVP_MAX_MD_SIZE);  // 256-bit hash
//     unsigned int len = 0;

//     // OpenSSL 不直接提供 keccak256，所以这里用 SHA3 算法
//     EVP_MD_CTX* ctx = EVP_MD_CTX_new();
//     EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    
//     KECCAK1600_CTX* keccak_ctx = reinterpret_cast<KECCAK1600_CTX*>((reinterpret_cast<EVP_MD_CTX_t*>(ctx))->md_data);
//     // cout << keccak_ctx->pad << endl;
//     keccak_ctx->pad = 0x01;

//     EVP_DigestUpdate(ctx, data.data() + 1, data.size() - 1);
//     EVP_DigestFinal_ex(ctx, hash.data(), &len);

//     EVP_MD_CTX_free(ctx);
//     hash.resize(len);  // Resize the hash to the correct length
//     return hash;
// }

// vector<unsigned char> keccak256(const vector<unsigned char>& data) {
//     sha3_context ctx;
//     sha3_Init256(&ctx);
//     sha3_SetFlags(&ctx, SHA3_FLAGS_KECCAK);  // 强制使用 Keccak 填充（0x01）
//     sha3_Update(&ctx, data.data(), data.size());
//     const uint8_t* hash = sha3_Finalize(const_cast<void*>(reinterpret_cast<const void*>(&ctx)));
//     return vector<unsigned char>(hash, hash + 32);
// }

vector<unsigned char> pbkdf2_hmac(string mnemonic) {
    const unsigned char salt[] = "mnemonic";
    const int iterations = 2048;
    const int key_length = 64; // 512 bits
    vector<unsigned char> derived_key(key_length);

    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), mnemonic.size(), salt, 8, iterations, EVP_sha512(), key_length, derived_key.data());

    return derived_key;
}

vector<unsigned char> hmac_sha512(const vector<unsigned char> &key, const vector<unsigned char> &msg) {
    vector<unsigned char> result(SHA512_DIGEST_LENGTH);
    unsigned int len = SHA512_DIGEST_LENGTH;
    HMAC(EVP_sha512(), key.data(), key.size(), msg.data(), msg.size(), result.data(), &len);
    return result;
}

// 将 vector<unsigned char> 转换为 OpenSSL 的 BIGNUM
BIGNUM* vector_to_bignum(const vector<unsigned char>& v) {
    return BN_bin2bn(v.data(), v.size(), NULL);
}

// 计算 SECP256K1 公钥
vector<unsigned char> private_key_to_public_key(const vector<unsigned char>& private_key, const bool is_compressed = true) {
    // 创建 SECP256K1 曲线的 EC_GROUP 对象
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (group == nullptr) {
        cerr << "Failed to create EC group" << endl;
        return {};
    }

    // 创建一个 EC_POINT 用来存储公钥
    EC_POINT* public_key_point = EC_POINT_new(group);
    if (public_key_point == nullptr) {
        cerr << "Failed to create EC point" << endl;
        EC_GROUP_free(group);
        return {};
    }

    // 将私钥转换为 BIGNUM
    BIGNUM* priv_bn = vector_to_bignum(private_key);
    if (priv_bn == nullptr) {
        cerr << "Failed to convert private key to BIGNUM" << endl;
        EC_POINT_free(public_key_point);
        EC_GROUP_free(group);
        return {};
    }

    // 计算公钥点
    if (EC_POINT_mul(group, public_key_point, priv_bn, NULL, NULL, NULL) != 1) {
        cerr << "Failed to calculate public key" << endl;
        BN_free(priv_bn);
        EC_POINT_free(public_key_point);
        EC_GROUP_free(group);
        return {};
    }

    int public_key_length = is_compressed ? 33 : 65;
    point_conversion_form_t point_conversion_form = is_compressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED;
    vector<unsigned char> public_key(public_key_length);
    if (EC_POINT_point2oct(group, public_key_point, point_conversion_form, public_key.data(), public_key.size(), NULL) == 0) {
        cerr << "Failed to convert public key to octet form" << endl;
        BN_free(priv_bn);
        EC_POINT_free(public_key_point);
        EC_GROUP_free(group);
        return {};
    }

    // 清理资源
    BN_free(priv_bn);
    EC_POINT_free(public_key_point);
    EC_GROUP_free(group);

    return public_key;
}

// 将字符串转换为 BIGNUM
BIGNUM* hex_to_bignum(const string& hex_str) {
    BIGNUM* bn = NULL;
    if (BN_hex2bn(&bn, hex_str.c_str()) == 0) {
        cerr << "Failed to convert hex string to BIGNUM" << endl;
        return NULL;
    }
    return bn;
}

// 将 SECP256K1 的阶 (Order) 转换为 BIGNUM
BIGNUM* order_bn = hex_to_bignum("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

// 计算新的私钥： (private_key + child_key) % ORDER_SECP256K1
vector<unsigned char> generate_private_key(
    const vector<unsigned char>& private_key,
    const vector<unsigned char>& child_key) {

    // 将私钥和子密钥转换为 BIGNUM
    BIGNUM* priv_bn = vector_to_bignum(private_key);
    BIGNUM* child_bn = vector_to_bignum(child_key);

    // 计算 (private_key + child_key) % ORDER_SECP256K1
    BIGNUM* sum_bn = BN_new();
    BN_add(sum_bn, priv_bn, child_bn);

    // 取模操作 (sum_bn % order_bn)
    BIGNUM* mod_bn = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_mod(mod_bn, sum_bn, order_bn, ctx);

    // 将结果转换为字节数组
    vector<unsigned char> result(32);
    BN_bn2bin(mod_bn, result.data());

    // 清理
    BN_free(priv_bn);
    BN_free(child_bn);
    BN_free(sum_bn);
    BN_free(mod_bn);

    return result;
}

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

void print_hash(unsigned char *hash, int length = 32) {
    for (int i = 0; i < length; i++) {
        printf("%02x", (unsigned char)hash[i]);
    }
    printf("\n");
}

vector<unsigned char> derive_tron_private_key(const vector<unsigned char> &seed) {
    //  1. 从种子生成主密钥
    vector<unsigned char> master_key = hmac_sha512({ 'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd' }, seed);
    vector<unsigned char> master_private_key(master_key.begin(), master_key.begin() + 32);
    vector<unsigned char> master_chain_code(master_key.begin() + 32, master_key.end());

    // 2. BIP-44 路径
    const uint32_t HARDENED_INDEX = 0x80000000;
    vector<uint32_t> path = {
        44 + HARDENED_INDEX,  // purpose
        195 + HARDENED_INDEX, // coin_type (195 for TRON)
        0 + HARDENED_INDEX,   // account
        0,                    // change
        0                     // address index
    };

    vector<unsigned char> private_key = master_private_key;
    vector<unsigned char> chain_code = master_chain_code;

    for (uint32_t index : path) {
        vector<unsigned char> data;
        if (index & HARDENED_INDEX) {
            // 硬化路径使用私钥
            data.push_back(0x00);
            data.insert(data.end(), private_key.begin(), private_key.end());
        } else {
            // 非硬化路径使用公钥
            vector<unsigned char> compressed_public_key = private_key_to_public_key(private_key, true);
            data.insert(data.end(), compressed_public_key.begin(), compressed_public_key.end());
        }
        data.push_back((index >> 24) & 0xFF);
        data.push_back((index >> 16) & 0xFF);
        data.push_back((index >> 8) & 0xFF);
        data.push_back(index & 0xFF);

        // 计算 HMAC-SHA512
        vector<unsigned char> child_key = hmac_sha512(chain_code, data);        
        // 更新私钥
        private_key = generate_private_key(private_key, { child_key.begin(), child_key.begin() + 32 });
        // 更新链码
        chain_code = vector<unsigned char>(child_key.begin() + 32, child_key.end());
    }

    return private_key;
}

string process_candidate(__uint128_t candidate) {
    // 计算校验和
    vector<unsigned char> entropy_bytes = int2bytes(candidate);
    unsigned char checksum = sha256(vector<unsigned char>(entropy_bytes.data(), entropy_bytes.data() + 16))[0] >> 4;;

    // 计算助记词
    string word11 = BIP39_WORDLIST[(candidate >> 7) & 0x7FF];
    string word12 = BIP39_WORDLIST[((candidate & 0x7F) << 4) | checksum];
    string mnemonic = pre_words_str + " " + word11 + " " + word12;

    // 计算派生密钥
    vector<unsigned char> seed = pbkdf2_hmac(mnemonic);
    vector<unsigned char> private_key = derive_tron_private_key(seed);
    vector<unsigned char> public_key = private_key_to_public_key(private_key, false);

    // 计算地址
    public_key = vector<unsigned char>(public_key.begin() + 1, public_key.end());
    print_hash(public_key.data(), 64);
    vector<unsigned char> primitive_addr = keccak256(public_key);
    print_hash(primitive_addr.data(), 32);

    primitive_addr = vector<unsigned char>(primitive_addr.end() - 20, primitive_addr.end());
    primitive_addr.insert(primitive_addr.begin(), 0x41); // 添加地址前缀
    vector<unsigned char> digest = sha256(sha256(primitive_addr));
    vector<unsigned char> checksum_tron = vector<unsigned char>(digest.begin(), digest.begin() + 4);
    primitive_addr.insert(primitive_addr.end(), checksum_tron.begin(), checksum_tron.end());
    string address = EncodeBase58(primitive_addr);
    cout << "Address: " << address << endl;
    
    if (address == target_address) {
        return mnemonic;
    }

    return "1";
}

int main() {
    cout << "Hello, World!" << endl;

    __uint128_t pre_entropy = 0;
    istringstream words_stream(pre_words_str);
    string word;
    while (words_stream >> word) {
        auto it = lower_bound(BIP39_WORDLIST.begin(), BIP39_WORDLIST.end(), word);
        int idx = distance(BIP39_WORDLIST.begin(), it);
        pre_entropy <<= 11;
        pre_entropy |= idx;
    }
    pre_entropy <<= 18;

    for (int c = 0; c < (1 << 18); ++c) {
        string result = process_candidate(pre_entropy | c);
        if (result.size() > 0) {
            cout << "\nFound words: " << result << endl;
            return 0;
        }
    }

    cout << "No matching words found." << endl;
    return 0;
}

