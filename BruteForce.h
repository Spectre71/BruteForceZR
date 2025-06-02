// bruteFroce.h
#pragma once
// this header file includes all necessary includes and functions for brute-force cracking zip files with SHA-256 encryption

#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <zlib.h>
#include <zip.h>
#include <cmath>

// ------ Global variables for thread synchronization ------
std::atomic<bool> found(false);
std::atomic<uint64_t> counter(0);
std::string correct_password;
std::mutex mtx;

// ------ Functions for brute-force cracking zip files ------
// 
// Generate password from a counter value
std::string generate_password(uint64_t n, const std::string& charset, int length);

// Test password against ZIP file
bool validate_password(const std::string& file_path, const std::string& password);

// Parallel brute-force function
void brute_worker(const std::string& file_path, const std::string& charset, int length, uint64_t start, uint64_t end);

// Displys help message
void show_help();

// Main function to run the brute-force attack
bool run_bruteforce();

// ------ USAGE ------
/*
CMD ARGUMENTS:

<zip_file>: Path to the ZIP file you want to crack.
<charset>: String of characters to use in passwords (e.g., abc123 or abcdefghijklmnopqrstuvwxyz).
<min_length>: Minimum password length to try.
<max_length>: Maximum password length to try.
[threads]: (Optional) Number of threads to use. Defaults to the number of CPU cores.

EXAMPLE USAGE:
.\zip_brute.exe "testLkd.zip" "abc123" 3 5 8 -> This tries all passwords of length 3 to 5 using the characters a, b, c, 1, 2, and 3 while also using 8 threads

BEST CHARSETS TO USE:
- Lowercase letters: abcdefghijklmnopqrstuvwxyz
- Uppercase letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
- Digits: 0123456789
- Special characters: !@#$%^&*()-_=+[]{};:'",.<>?/|`~
- Combination: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'",.<>?/|`~
- Custom: You can create your own charset by combining any of the above characters.

- Note: The more characters you include, the longer the cracking process will take.
- Note: The charset should not be too long, as it will increase the time taken to crack the password exponentially.

COMPILATION:
g++ -O3 -std=c++23 -I "Path\to\packages\libzip-c.1.11.3.1\include"  -L "Path\to\packages\libzip-c.1.11.3.1\lib\windows\x64\release" -o zip_brute BruteForceZR.cpp -lzip -pthread -lz

- Note: Make sure to link against the libzip library and include the necessary headers.
- Note: You may need to adjust the compilation command based on your system and compiler.
- Note: Make sure all required dll files (found in bin) are where the .exe file is located, or in a directory that is in your PATH environment variable.

DEPENDENCIES:
- libzip: A library for reading, creating, and modifying zip archives. You can find it at https://libzip.org/
	- NuGet->libzip-c

---------------LEGACY FUNCTIONS: (These functions are not used in the current implementation but are kept for reference)-----------
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
----------------------------------------------------------------------------------------
}*/
