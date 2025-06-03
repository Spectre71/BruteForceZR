# BruteForceZR

A C++ applet made for cracking ZIP files with modern and legacy encryptions, such as AES-128/256 and ZIPCrypto respectfully.

## Future
- add support for RAR files,
- CUDA computing for speed,
- *update readme, add userManual to `README.md`, explain how code works.*

## Features
- Allows full ZIP decryption with progress reporting,
- allows to specify which file in a zip to crack,
- can specify custom character sets or choose predefined ones,
- can specify number of CPU cores to work on decryption,
- full error/exception handling.

## User Manual
To use `BruteForceZR.exe`, simply launch it (open it in terminal with `.\BruteForceZR.exe`), and follow the prompts on screen -- really, it's straight fowrward. If you need an explanation of what the app does, and how it does it, there's currently a basic `help` section integrated into the app itself -- simply type "help" and hit enter. Essentially it opens up your specified ZIP file, checks how many files it includes, and starts generating passwords for the specified unit until it's found, then it asks you whether you want to rerun the process, or exit. There are also very simple instructions written in the header file of the applet, but since that might disappear one day, here's the overview:

- To compile the app using `g++`, run the following command:
```bash
g++ -O3 -std=c++23 -I "Path\to\packages\libzip-c.1.11.3.1\include"  -L "Path\to\packages\libzip-c.1.11.3.1\lib\windows\x64\release" -o BruteForceZR BruteForceZR.cpp -lzip -pthread -lz
```
- Move the dll files into the location of the newly created `BruteForceZR.exe`,
- Use the app as is (or wait for CUDA port -- may be worthwhile).

## Requirements
- Visual Studio
- g++ compiler (optional, but useful)
- NuGet package manager
- `libzip-c` (currently `1.11.3.1`), found under NuGet packages
- *Do not forget to include apppropriate libraries such as `zlib.h` and `zip.h`, which are part of `libzip-c`*

## Notes
*Best charsets to use:*
- Lowercase letters: abcdefghijklmnopqrstuvwxyz
- Uppercase letters: ABCDEFGHIJKLMNOPQRSTUVWXYZ
- Digits: 0123456789
- Special characters: !@#$%^&*()-_=+[]{};:'",.<>?/|`~
- Combination: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:'",.<>?/|`~
- Custom: You can create your own charset by combining any of the above characters.

  - Side Note: The more characters you include, the longer the cracking process will take.
  - Side Note: The charset should not be too long, as it will increase the time taken to crack the password exponentially.

## Fun Facts
- the app used to be cmd argument based with bare bones progress reporting. This tried all passwords of length 3 to 5 using the characters a, b, c, 1, 2, and 3 while also using 8 threads. Its operational procedure was:
```bash
.\zip_brute.exe "testLkd.zip" "abc123" 3 5 8
```
- these used to be arguments: `<zip_file>`, `<charset>`, `<min_length>`, `<max_length>`, `<threads>`.
