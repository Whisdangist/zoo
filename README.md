sudo apt update
sudo apt install -y build-essential git
sudo apt install openssl libssl-dev
sudo apt install libsecp256k1-dev

g++ test_3.cc -O3 -march=native -flto -ffast-math -o test -lssl -lcrypto -lsecp256k1 && ./test
