sudo apt update
sudo apt install -y build-essential git openssl libssl-dev libsecp256k1-dev
git clone https://github.com/Whisdangist/zoo.git
cd zoo

g++ test_3.cc -O3 -march=native -flto -ffast-math -o test -lssl -lcrypto -lsecp256k1 -lpthread && nohup ./test 0 >out.log 2>&1
