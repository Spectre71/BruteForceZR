// BruteForceZR.cpp

#include "BruteForce.h"

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

// List all files in the ZIP and return their names
std::vector<std::string>list_zip_files(const std::string& file_path) {
    std::vector<std::string> files;
    int error;
    zip_t* archive = zip_open(file_path.c_str(), ZIP_RDONLY, &error);
    if (!archive) {
        std::cerr << "Failed to open ZIP file.\n";
        return files;
    }
    zip_int64_t num_files = zip_get_num_entries(archive, 0);
    for (zip_uint64_t i = 0; i < num_files; i++) {
		const char* name = zip_get_name(archive, i, 0);
        if (name) {
			files.push_back(name);
        }
    }
    zip_close(archive);
    return files;
}

// Validate password by checking decrypted content CRC
bool validate_password(const std::string& file_path, zip_uint64_t file_index, const std::string& password) {
    int error;
    zip_t* archive = zip_open(file_path.c_str(), ZIP_RDONLY, &error);
    if (!archive) return false;

    // Get first file's metadata
    zip_stat_t stat;
    if (zip_stat_index(archive, file_index, 0, &stat) != 0) {
        zip_close(archive);
        return false;
    }

    // Attempt to open encrypted file
    zip_file_t* file = zip_fopen_index_encrypted(archive, file_index, ZIP_FL_ENC_GUESS, password.c_str());
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

    return (computed_crc == stat.crc);
}

// Parallel brute-force worker
void brute_worker(const std::string& file_path, const std::string& charset, int length, uint64_t start, uint64_t end, zip_uint64_t file_index, std::atomic<bool>& found_local, std::string& found_password, int thread_id = 0) {
    for (uint64_t i = start; !found_local && i < end; ++i) {
        std::string password = generate_password(i, charset, length);

        if (thread_id == 0 && (i % 100 == 0)) {
            std::cout << "\r\033[KTesting: " << password << std::flush; // Print current password being tested
        }

        if (validate_password(file_path, file_index, password)) {
            std::lock_guard<std::mutex> lock(mtx);
            if (!found_local) {
                found_local = true;
                found_password = password;
            }
            return;
        }
        ++counter;
    }
}

void show_help() {
    std::cout << "\n                     === \033[32mBruteForceZR\033[0m Help ===\n\n";
    std::cout << "This app attempts to brute-force the password of a ZIP file using a given character set and password length range.\n\n";
    std::cout << "You will be prompted for:\n";
    std::cout << "  - Path to the ZIP file\n";
    std::cout << "  - Charset (characters to use in passwords, e.g., abc123\n";
    std::cout << "  - Minimum and maximum password length\n";
    std::cout << "  - Number of threads (0 for auto-detect)\n";
    std::cout << "The app will then try all possible combinations in the given range.\n\n";
    std::cout << "Best charsets:\n";
    std::cout << "  - For numeric passwords: '0123456789'\n";
    std::cout << "  - For alphanumeric passwords: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'\n";
    std::cout << "  - For complex passwords: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'\n";
    std::cout << "The more characters and longer the password, the longer it will take.\n\n";
    std::cout << "Press Enter to continue...\n";
    std::cin.get();
}

bool run_bruteforce() {
    // Reset global state for each run
    found = false;
    counter = 0;
    correct_password.clear();

    std::string file_path;
    std::string charset;
    int min_len, max_len, num_threads;

    std::cout << "Enter path to ZIP file: ";
    std::getline(std::cin, file_path);
	std::cout << "\n"; // Add a newline for better readability

    // List files in ZIP
    std::vector<std::string> files = list_zip_files(file_path);
    if (files.empty()) {
        std::cout << "No files found in ZIP or failed to open ZIP.\n";
        return false;
    }
    std::cout << "ZIP contains " << files.size() << " file(s):\n";
    for (size_t i = 0; i < files.size(); ++i) {
        std::cout << "  [" << i << "] " << files[i] << "\n";
    }
	std::cout << "\n";

    std::cout << "Choose a charset option:\n";
    std::cout << "  1. Numeric (0123456789)\n";
    std::cout << "  2. Lowercase (abcdefghijklmnopqrstuvwxyz)\n";
    std::cout << "  3. Uppercase (ABCDEFGHIJKLMNOPQRSTUVWXYZ)\n";
    std::cout << "  4. Alphanumeric (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)\n";
    std::cout << "  5. Complex (abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?)\n";
    std::cout << "  6. Custom\n";
    std::cout << "Enter your choice (1-6): ";

    int charset_choice = 0;
    while (!(std::cin >> charset_choice) || charset_choice < 1 || charset_choice > 6) {
        std::cout << "Please enter a valid option (1-6): ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear input buffer

    switch (charset_choice) {
    case 1:
        charset = "0123456789";
        break;
    case 2:
        charset = "abcdefghijklmnopqrstuvwxyz";
        break;
    case 3:
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        break;
    case 4:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        break;
    case 5:
        charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        break;
    case 6:
        std::cout << "Enter your custom charset: ";
        std::getline(std::cin, charset);
		std::cout << "\n"; // Add a newline for better readability
        break;
    }

    std::cout << "Enter minimum password length: ";
    while (!(std::cin >> min_len) || min_len <= 0) {
        std::cout << "Please enter a valid positive integer for minimum length: ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    std::cout << "Enter maximum password length: ";
    while (!(std::cin >> max_len) || max_len < min_len) {
        std::cout << "Please enter a valid integer >= minimum length: ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    std::cout << "Enter number of threads (0 for auto): ";
    while (!(std::cin >> num_threads) || num_threads < 0) {
        std::cout << "Please enter a valid non-negative integer: ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    if (num_threads == 0) {
        num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 1;
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Clear input buffer

    std::set<size_t> cracked_files;
    while (true) {
        size_t file_index = 0;
        std::cout << "\nEnter the index of the file you want to crack (0-" << files.size() - 1 << "): ";
        while (!(std::cin >> file_index) || file_index >= files.size() || cracked_files.count(file_index)) {
            if (cracked_files.count(file_index)) {
                std::cout << "File already cracked. Choose another: ";
            }
            else {
                std::cout << "Please enter a valid file index: ";
            }
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        }
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::atomic<bool> found_local(false);
        std::string found_password;
        counter = 0;

        for (int len = min_len; len <= max_len && !found_local; ++len) {
            const uint64_t total = static_cast<uint64_t>(pow(charset.size(), len));
            const uint64_t chunk = total / num_threads;

            std::vector<std::thread> threads;
            for (int i = 0; i < num_threads; ++i) {
                uint64_t start = i * chunk;
                uint64_t end = (i == num_threads - 1) ? total : start + chunk;
                threads.emplace_back(brute_worker, file_path, charset, len, start, end, file_index, std::ref(found_local), std::ref(found_password), i);
            }

            for (auto& t : threads) t.join();
            if (found_local) break;
        }

        if (found_local) {
            std::cout << "\n\nFound password for '" << files[file_index] << "': " << found_password << "\n";
            std::cout << "Total attempts: " << counter.load() << std::endl;
            std::cout << "\n";
            cracked_files.insert(file_index);
        }
        else {
            std::cout << "Password not found for '" << files[file_index] << "'\n\n";
        }

        // Ask user if they want to continue
        if (cracked_files.size() == files.size()) {
            std::cout << "All files have been processed.\n";
            break;
        }
        std::string cont;
        std::cout << "Do you want to crack another file? (y/n): ";
        std::getline(std::cin, cont);
        if (cont != "y" && cont != "Y") break;
    }
    
    std::cout << "Cracking session finished. Press Enter to continue...\n";
    std::cin.get();
    return true;
}

bool first_run() {
	static bool shown = false; // static variable to track if help has been shown
	if (!shown) {
		std::cout << "\n                    === Welcome to \033[32mBruteForceZR\033[0m ===\n\n";
		std::cout << "---------------------------------------------------------------------------\n";
		std::cout << "This software was developed as part of cybersecurity research endeavors   |\n";
        std::cout << "Author: Spectre 71                                                        |\n";
		std::cout << "---------------------------------------------------------------------------\n\n";
		std::cout << "Type '\033[33mcrack\033[0m' to crack a zip file, '\033[34mhelp\033[0m' for instructions, or '\033[31mexit\033[0m' to quit: ";
		shown = true;
		return true; // Return true if help has not been shown yet
	}
	return false; // Return false if help has already been shown
}

int main() {
    while (true) {
        std::string choice; 
        bool is_first = first_run(); // Show welcome message only once
        if (!is_first) {
            std::cout << "new input: ";
        }
        std::getline(std::cin, choice);
		std::cout << "\n"; // Add a newline for better readability

        if (choice == "help" || choice == "Help" || choice == "HELP") {
            show_help();
        }
        else if (choice == "crack" || choice == "Crack" || choice == "CRACK") {
            run_bruteforce();
        }
        else if (choice == "exit" || choice == "Exit" || choice == "EXIT" || choice.empty()) {
            std::cout << "Exiting BruteForceZR. Goodbye!\n";
            break;
        }
        else {
            std::cout << "Unknown option. Please type 'crack', 'help', or 'exit'.\n";
        }
    }
    return 0;
}