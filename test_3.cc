#include <bits/stdc++.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <secp256k1.h>
#include "keccak256.h"
#include "base58.h"
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
const string pre_words_str = "dentist gauge whisper cattle lemon pink benefit ship subject";
const vector<unsigned char> decoded_target_address = DecodeBase58("TEyy2fr2xMYwwsZUxmNx7HD4LT9WhEorPP");


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
std::vector<unsigned char> private_key_to_public_key(const std::vector<unsigned char>& private_key, const bool is_compressed = true) {
    // 初始化libsecp256k1上下文
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    // 检查私钥长度是否正确（32字节）
    if (private_key.size() != 32) {
        secp256k1_context_destroy(ctx);
        throw std::invalid_argument("Private key must be 32 bytes long.");
    }

    // 创建公钥变量
    secp256k1_pubkey pubkey;

    // 从私钥生成公钥
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key.data())) {
        secp256k1_context_destroy(ctx);
        throw std::runtime_error("Failed to create public key from private key.");
    }

    // 根据是否压缩选择公钥输出格式
    size_t pubkey_len = is_compressed ? 33 : 65;
    std::vector<unsigned char> public_key(pubkey_len);

    // 将公钥序列化为字节数组
    secp256k1_ec_pubkey_serialize(ctx, public_key.data(), &pubkey_len, &pubkey, is_compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

    // 清理上下文
    secp256k1_context_destroy(ctx);

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
    string word10 = BIP39_WORDLIST[(candidate >> 18) & 0x7FF];
    string word11 = BIP39_WORDLIST[(candidate >> 7) & 0x7FF];
    string word12 = BIP39_WORDLIST[((candidate & 0x7F) << 4) | checksum];
    string mnemonic = pre_words_str + " " + word10 + " " + word11 + " " + word12;

    // 计算派生密钥
    vector<unsigned char> seed = pbkdf2_hmac(mnemonic);
    vector<unsigned char> private_key = derive_tron_private_key(seed);
    vector<unsigned char> public_key = private_key_to_public_key(private_key, false);

    // 计算地址
    public_key = vector<unsigned char>(public_key.begin() + 1, public_key.end());
    vector<unsigned char> primitive_addr = keccak256(public_key);

    if (vector<unsigned char>(primitive_addr.end() - 20, primitive_addr.end()) == vector<unsigned char>(decoded_target_address.begin() + 1, decoded_target_address.end() - 4)) {
        return mnemonic;
    }

    return "";
}

std::atomic<bool> stop_threads(false);

int worker(__uint128_t pre_entropy, int worker_id, int bits = 3) {
    for (int c = 0; c < (1 << (29 - bits)); ++c) {
        if (stop_threads) return 0;
        string result = process_candidate(pre_entropy | (worker_id << (29 - bits)) | c);
        if (result.size() > 0) {
            cout << "\nFound words: " << result << endl;
            stop_threads = true;
            return 1;
        }
        if (c % 1000 == 0) {
            cout << "Processed " << c << " candidates." << endl;
        }
    }
    cout << "No matching words found." << endl;
    return 0;
}

// #define TEST

void solve() {    
    __uint128_t pre_entropy = 0;
    istringstream words_stream(pre_words_str);
    string word;
    while (words_stream >> word) {
        auto it = lower_bound(BIP39_WORDLIST.begin(), BIP39_WORDLIST.end(), word);
        int idx = distance(BIP39_WORDLIST.begin(), it);
        pre_entropy <<= 11;
        pre_entropy |= idx;
    }
    pre_entropy <<= 29;

    #ifndef TEST
        vector<thread> threads;
        int num_bits = 4;
        for (int i = 0; i < (1 << num_bits); ++i) {
            threads.push_back(thread(worker, pre_entropy, i, num_bits));
        }
        for (auto& t : threads) {
            t.join();
        }
    #endif

    #ifdef TEST
        worker(pre_entropy, 0, 8);
    #endif

    std::cout << "All threads have completed." << std::endl;
}

int main() {
    cout << "Hello, World!" << endl;

    auto start = std::chrono::high_resolution_clock::now();    
    solve();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Task executed in " << duration.count() / 1000 << " seconds." << std::endl;

    return 0;
}

