#include "master_password.h"
#include <fstream>
#include <cryptopp/osrng.h>
#include <cryptopp/argon2.h>
#include <cryptopp/files.h>

// Use the Crypto++ namespace
using namespace CryptoPP;

void MasterPassword::setPassword(const std::string& password) {
    // 1. Generate a cryptographically secure salt
    m_salt.resize(16); // 16 bytes is a good default for salt
    AutoSeededRandomPool prng;
    prng.GenerateBlock(m_salt.data(), m_salt.size());

    // 2. Hash the password using Argon2id
    m_hash.resize(32); // 32 bytes for the hash is standard (256 bits)

    Argon2id argon2;
    argon2.DeriveKey(
        m_hash.data(), m_hash.size(),
        (const byte*)password.data(), password.size(),
        m_salt.data(), m_salt.size(),
        1, // Time cost (t)
        65536, // Memory cost (m) in KiB
        1 // Parallelism (p)
    );
}

bool MasterPassword::verifyPassword(const std::string& password) const {
    if (!isPasswordSet()) {
        return false; // No password has been set yet
    }

    std::vector<byte> verification_hash(m_hash.size());

    Argon2id argon2;
    argon2.DeriveKey(
        verification_hash.data(), verification_hash.size(),
        (const byte*)password.data(), password.size(),
        m_salt.data(), m_salt.size(),
        1, // Time cost (t) - must match what was used for hashing
        65536, // Memory cost (m) - must match
        1 // Parallelism (p) - must match
    );

    // Constant-time comparison to prevent timing attacks
    return CryptoPP::VerifyBufsEqual(m_hash.data(), verification_hash.data(), m_hash.size());
}

bool MasterPassword::saveToFile(const std::string& filename) const {
    try {
        std::ofstream file(filename, std::ios::out | std::ios::binary);
        if (!file) return false;

        // Write salt size, then salt
        size_t salt_size = m_salt.size();
        file.write(reinterpret_cast<const char*>(&salt_size), sizeof(salt_size));
        file.write(reinterpret_cast<const char*>(m_salt.data()), salt_size);

        // Write hash size, then hash
        size_t hash_size = m_hash.size();
        file.write(reinterpret_cast<const char*>(&hash_size), sizeof(hash_size));
        file.write(reinterpret_cast<const char*>(m_hash.data()), hash_size);

        return file.good();
    } catch (...) {
        return false;
    }
}

bool MasterPassword::loadFromFile(const std::string& filename) {
    try {
        std::ifstream file(filename, std::ios::in | std::ios::binary);
        if (!file) return false;

        // Read salt size, then salt
        size_t salt_size = 0;
        file.read(reinterpret_cast<char*>(&salt_size), sizeof(salt_size));
        if (!file || salt_size == 0) return false;
        m_salt.resize(salt_size);
        file.read(reinterpret_cast<char*>(m_salt.data()), salt_size);

        // Read hash size, then hash
        size_t hash_size = 0;
        file.read(reinterpret_cast<char*>(&hash_size), sizeof(hash_size));
        if (!file || hash_size == 0) return false;
        m_hash.resize(hash_size);
        file.read(reinterpret_cast<char*>(m_hash.data()), hash_size);

        return file.good();
    } catch (...) {
        return false;
    }
}

bool MasterPassword::isPasswordSet() const {
    return !m_salt.empty() && !m_hash.empty();
}
