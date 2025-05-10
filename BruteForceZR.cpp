// BruteForceZR.cpp

#include "bruteForce.h"

// Generate passwords from numeric index
std::string generate_password(uint64_t n, const std::string& charset, int length) {
    std::string password;
    int base = charset.size();
    for (int i = 0; i < length; ++i) {
        password.push_back(charset[n % base]);
        n /= base;
    }
    std::reverse(password.begin(), password.end());
    return password;
}

// Validate password by checking decrypted content CRC
bool validate_password(const std::string& file_path, const std::string& password) {
    int error;
    zip_t* archive = zip_open(file_path.c_str(), ZIP_RDONLY, &error);
    if (!archive) return false;

    // Get first file's metadata
    zip_stat_t stat;
    if (zip_stat_index(archive, 0, 0, &stat) != 0) {
        zip_close(archive);
        return false;
    }
    const unsigned long stored_crc = stat.crc;

    // Attempt to open encrypted file
    zip_file_t* file = zip_fopen_index_encrypted(archive, 0, ZIP_FL_ENC_GUESS, password.c_str());
    if (!file) {
        zip_close(archive);
        return false;
    }

    // Read and validate content
    std::vector<char> buffer(stat.size);
    zip_int64_t bytes_read = zip_fread(file, buffer.data(), buffer.size());
    zip_fclose(file);
    zip_close(archive);

    if (bytes_read != static_cast<zip_int64_t>(stat.size)) return false;

    // Compute CRC of decrypted data
    uLong computed_crc = crc32(0L, Z_NULL, 0);
    computed_crc = crc32(computed_crc, reinterpret_cast<Bytef*>(buffer.data()), buffer.size());

    return (computed_crc == stored_crc);
}

// Parallel brute-force worker
void brute_worker(const std::string& file_path, const std::string& charset, int length, uint64_t start, uint64_t end) {
    for (uint64_t i = start; !found && i < end; ++i) {
        std::string password = generate_password(i, charset, length);
        if (validate_password(file_path, password)) {
            std::lock_guard<std::mutex> lock(mtx);
            if (!found) {
                found = true;
                correct_password = password;
            }
            return;
        }
        ++counter;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <zip_file> <charset> <min_len> <max_len> [threads]\n";
        return 1;
    }

    const std::string file_path = argv[1];
    const std::string charset = argv[2];
    const int min_len = std::stoi(argv[3]);
    const int max_len = std::stoi(argv[4]);
    const int num_threads = (argc > 5) ? std::stoi(argv[5]) : std::thread::hardware_concurrency();

    for (int len = min_len; len <= max_len && !found; ++len) {
        const uint64_t total = static_cast<uint64_t>(pow(charset.size(), len));
        const uint64_t chunk = total / num_threads;

        std::vector<std::thread> threads;
        for (int i = 0; i < num_threads; ++i) {
            uint64_t start = i * chunk;
            uint64_t end = (i == num_threads - 1) ? total : start + chunk;
            threads.emplace_back(brute_worker, file_path, charset, len, start, end);
        }

        for (auto& t : threads) t.join();
        if (found) break;
    }

    if (found) {
        std::cout << "Found password: " << correct_password << std::endl;
		std::cout << "Total attempts: " << counter.load() << std::endl;
		std::cout << "Press Enter to exit..." << std::endl;
		std::cin.get();
        return 0;
    }

    std::cout << "Password not found" << std::endl;
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
    return 1;
}