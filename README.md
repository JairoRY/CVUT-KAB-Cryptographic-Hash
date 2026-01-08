# Cryptographic Hash Functions and Partial Collisions

This repository contains a C++ implementation for finding partial hash collisions. The project was developed as part of the Cryptography and Security (KAB) course at the Czech Technical University (CVUT) in Prague, during an academic exchange from the Universitat Politècnica de Catalunya (UPC).

The primary objective of this task is to utilize the OpenSSL library to find a message that produces a hash with a specific number of leading zero bits.

## Project Structure

The project consists of a single source file:

* **TASK2_elyazjai.cpp**: The core implementation that uses the OpenSSL EVP API to compute cryptographic hashes. It includes the logic to iterate through messages and check their binary representation for the required number of leading zero bits.

## Getting Started

### Prerequisites

You will need a C++ compiler and the OpenSSL development headers installed on your system.

On Ubuntu/Debian:

```bash
sudo apt-get install g++ libssl-dev

```

### Usage

1. **Clone the repository:**
```bash
git clone https://github.com/JairoRY/CVUT-KAB-Task-2.git
cd CVUT-KAB-Task-2

```


2. **Compile the program:**
Ensure you link the OpenSSL crypto library during compilation:
```bash
g++ TASK2_elyazjai.cpp -o task2 -lcrypto

```


3. **Run the program:**
```bash
./task2

```



## Implementation Details

The solution focuses on the following cryptographic concepts:

* **OpenSSL EVP API**: Utilizing a high-level interface for cryptographic functions, allowing the program to support multiple hash algorithms interchangeably.
* **Partial Collision Finding**: Implementing a brute-force approach to find a message that results in a hash starting with a specific bit pattern.
* **Bitwise Inspection**: Converting hash bytes into a bitstream to verify the leading zero condition accurately.
* **Performance**: Optimized searching to demonstrate the computational difficulty of finding collisions as the required number of zero bits increases.
