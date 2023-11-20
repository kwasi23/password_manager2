# password_manager2
Overview

This Python application is a basic password manager that provides a graphical user interface (GUI) for managing passwords. It uses the Tkinter library for the GUI, SQLite for database storage, and the Python Crypto library for password encryption and decryption. The application allows users to store, retrieve, update, and delete passwords for various services or websites.
Features

    User Authentication: The application includes a simple login system with predefined username and password credentials. Users must enter the correct username and password to access the password manager's features.

    Database Storage: Passwords are securely stored in an SQLite database. The database is initialized when the application is launched, and a table named "passwords" is created to store service names and their corresponding encrypted passwords.

    Password Encryption: Passwords are encrypted using the AES encryption algorithm before being stored in the database. This ensures that sensitive information is protected.

    CRUD Operations: Users can perform the following operations on stored passwords:
        Add Password: Users can add passwords for various services. Optionally, a random password can be generated.
        Get Password: Users can retrieve passwords for specific services.
        Update Password: Users can update existing passwords.
        Delete Password: Users can delete passwords for services they no longer need.

    Password Generation: The application includes a feature to generate random passwords with a specified length and a combination of letters, digits, and special characters.

    Dynamic Button Sizing: The buttons in the main application window automatically adjust their size based on the window dimensions to provide an optimal user experience.

Usage

    Launch the Application: Run the script, and the application's login window will appear.

    Login: Enter the predefined username and password to access the main application window. If authentication is successful, the main window will appear.

    Main Application Window:
        Use the "Add Password" button to add new passwords for services or websites.
        Use the "Get Password" button to retrieve passwords for specific services.
        Use the "Update Password" button to update existing passwords.
        Use the "Delete Password" button to delete passwords for services you no longer need.

    Password Generation: When adding a new password, you can leave the password field blank to generate a random password.

    Dynamic Button Sizing: The buttons in the main application window adjust their size dynamically based on the window's dimensions.

    Logout: To exit the application, simply close the main application window, and the script will terminate.

Dependencies

This application relies on the following Python libraries and modules:

    tkinter: For the graphical user interface.
    sqlite3: For managing the SQLite database.
    Crypto.Cipher: For AES encryption and decryption.
    Crypto.Random: For generating random bytes.
    base64: For encoding and decoding data.
    os: For file system operations.
    string and random: For password generation.

Security

    Passwords are securely encrypted before being stored in the database using the AES encryption algorithm.
    An encryption key is generated and stored locally, ensuring that only authorized users can decrypt the passwords.
    User authentication is required to access the password manager, enhancing security.
