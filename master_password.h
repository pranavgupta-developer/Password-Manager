#ifndef MASTER_PASSWORD_H
#define MASTER_PASSWORD_H

#include <string>
#include <vector>

class MasterPassword {
public:
    // Sets a new master password, generating a new salt and hash.
    void setPassword(const std::string& password);

    // Verifies a password attempt against the stored salt and hash.
    bool verifyPassword(const std::string& password) const;

    // Saves the salt and hash to a file.
    bool saveToFile(const std::string& filename) const;

    // Loads the salt and hash from a file.
    bool loadFromFile(const std::string& filename);

    // Checks if a password has been set.
    bool isPasswordSet() const;

private:
    std::vector<byte> m_salt;
    std::vector<byte> m_hash;
};

#endif // MASTER_PASSWORD_H
