#include <iostream>
#include <string>
#include "master_password.h"

const std::string KEY_FILE = "master_key.dat";

void createNewPassword(MasterPassword& mp) {
    std::string password, confirm_password;
    std::cout << "Creating a new master password." << std::endl;

    do {
        std::cout << "Enter your new master password: ";
        std::getline(std::cin, password);

        std::cout << "Confirm your master password: ";
        std::getline(std::cin, confirm_password);

        if (password != confirm_password) {
            std::cout << "Passwords do not match. Please try again." << std::endl;
        }
    } while (password != confirm_password);

    mp.setPassword(password);
    if (mp.saveToFile(KEY_FILE)) {
        std::cout << "Master password has been set and saved successfully." << std::endl;
    } else {
        std::cerr << "Error: Could not save the master password to file." << std::endl;
    }
}

void verifyExistingPassword(MasterPassword& mp) {
    std::string password_attempt;
    std::cout << "Please enter your master password to unlock: ";
    std::getline(std::cin, password_attempt);

    if (mp.verifyPassword(password_attempt)) {
        std::cout << "Access granted. Welcome back!" << std::endl;
        // You can now proceed to load the rest of your password manager data
    } else {
        std::cout << "Access denied. Incorrect password." << std::endl;
    }
}

int main() {
    MasterPassword master_password;

    if (master_password.loadFromFile(KEY_FILE)) {
        // A password has been set, so we need to verify it
        std::cout << "Master password file found." << std::endl;
        verifyExistingPassword(master_password);
    } else {
        // No password has been set yet
        std::cout << "No master password file found." << std::endl;
        createNewPassword(master_password);
    }

    return 0;
}
