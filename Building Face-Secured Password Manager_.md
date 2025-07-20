

# **Building a Secure C++ Password Manager with Face Detection: A Comprehensive Architectural and Implementation Guide**

## **Executive Summary**

This report outlines the comprehensive development of a Windows desktop password manager in C++ that integrates face detection and recognition for secure access. The project aims to combine artificial intelligence (AI) with real-world security principles, providing hands-on experience with C++, file handling, OpenCV, and advanced encryption techniques. The recommended technology stack includes Visual Studio as the primary Integrated Development Environment (IDE) with CMake and vcpkg for build and dependency management. For secure password storage, Argon2id is advocated as the master password hashing algorithm, with AES-GCM for data encryption, employing PBKDF2 for key derivation and cryptographically secure random number generators (CSRNGs) for salts and Initialization Vectors (IVs). Face detection and recognition will leverage OpenCV's YuNet model for robust performance and the Local Binary Patterns Histograms (LBPH) algorithm for authentication. Qt is identified as the optimal User Interface (UI) framework due to its comprehensive features and seamless integration capabilities. The report emphasizes a layered architectural approach, secure coding practices, and thorough testing strategies to ensure a robust and reliable application.

## **1\. Introduction to the Project**

### **Defining the Password Manager: Features and Security Imperatives**

The objective of this project is to construct a sophisticated password manager tailored for the Windows desktop environment. This application is designed to securely store and manage a user's sensitive login credentials. Beyond conventional password management, a distinctive feature of this system is its integration of a webcam-based face detection and recognition mechanism. This biometric layer serves as a primary access gate, ensuring that only the authorized user can retrieve saved passwords. The core functionality revolves around the secure storage of encrypted passwords within a local file, accessible only after successful facial authentication.

The paramount concern throughout the development of this application is security. Given that the system handles highly sensitive personal data, robust cryptographic measures are indispensable. This necessitates the implementation of strong hashing algorithms for password verification, advanced encryption standards for data at rest, and meticulous key management practices. The design must prioritize data confidentiality, integrity, and availability, while simultaneously guarding against common software vulnerabilities.

### **Project Goals: Combining AI, C++, and Security for Hands-on Experience**

This endeavor serves as a practical exploration into the convergence of artificial intelligence, C++ programming, and cybersecurity. A primary goal is to provide a rich, hands-on learning experience in several critical technical domains. Developers will gain proficiency in C++ programming, including advanced concepts such as file handling and memory management. The integration of OpenCV will offer practical exposure to computer vision techniques, specifically face detection and recognition, demonstrating how AI can enhance real-world security applications. Furthermore, the project delves deep into cryptographic principles, encompassing hashing, salting, key stretching, and symmetric encryption, thereby solidifying understanding of secure data protection.

The project uniquely positions AI (computer vision) as a core security feature, enabling a "face unlock" mechanism to protect sensitive data. This practical application of AI in a security context underscores the interdisciplinary nature of modern software development. By building such a system, developers can observe firsthand the challenges and solutions involved in safeguarding digital assets using advanced technological paradigms.

### **Architectural Overview: A Layered Approach for Modularity and Security**

A well-defined software architecture is the foundational blueprint for any complex application, dictating how different components interact and fit together.1 For a security-critical application like a password manager, adopting a layered architectural pattern is crucial. This approach promotes a clear separation of concerns, enhances modularity, and improves overall maintainability and scalability.1 By dividing the system into distinct, independent layers, modifications within one layer can be made without significantly impacting others, thereby simplifying maintenance and reducing the risk of introducing new vulnerabilities. This structured design also facilitates independent testing of each subsystem, which is particularly beneficial for ensuring the robustness and security of individual components.

The layered architecture typically comprises a Presentation Layer (UI), an Application/Business Logic Layer, and a Data Access Layer.1 Security considerations, while permeating all layers, can be encapsulated within a dedicated security module or as cross-cutting concerns handled by specialized components. This systematic decomposition ensures that the application remains manageable, extensible, and resilient against potential threats.

## **2\. Setting Up Your C++ Development Environment**

### **Choosing the Right IDE: Visual Studio vs. VS Code for Windows Development**

For developing a Windows desktop application in C++, the choice of Integrated Development Environment (IDE) significantly impacts productivity and the development experience.

**Visual Studio (VS)** stands out as a highly robust and comprehensive IDE specifically tailored for C++ development on Windows.3 It offers a complete suite of C/C++ components suitable for desktop, mobile, Linux, and game development.3 Its debugging and diagnostics tools are exceptionally powerful, enabling developers to write and identify bug-free code efficiently.3 Visual Studio also provides advanced productivity features such as syntax colorization, code tooltips, Class View, and Call Hierarchy, which streamline code navigation and editing.3 Furthermore, it supports modern C++ standards, including C++11, C++14, and C++17.3 Installation typically involves selecting the "Desktop development with C++" workload, which bundles all necessary tools.4

**Visual Studio Code (VS Code)**, while a popular and lightweight code editor, requires additional extensions to function as a full-fledged C++ IDE.5 Extensions like "C/C++" and "Code Runner" are essential for C++ development within VS Code.5 It is frequently paired with the MinGW-w64 toolchain, which provides the GCC/g++ compiler and GDB debugger for Windows.7

**Code::Blocks** is another free and open-source IDE for C++ that provides basic project creation and compilation functionalities.5

For a C++ Windows desktop application, Visual Studio emerges as the superior choice. Its deep integration with the Windows ecosystem, comprehensive feature set, and robust debugging capabilities offer a professional and efficient development experience. While VS Code is versatile, Visual Studio's native support for Windows APIs and its advanced debugging tools provide a distinct advantage for developing complex, security-critical desktop applications.

### **Compiler and Build System Essentials: MSVC, MinGW, and CMake**

C++ compilers are fundamental tools that translate high-level C++ code into machine-understandable low-level language.5 On Windows, two prominent compilers are:

* **MSVC:** The Microsoft Visual C++ compiler, which is the default compiler integrated with Visual Studio.3  
* **MinGW-w64 (GCC/g++):** A widely used open-source compiler toolchain, often utilized when developing C++ applications with VS Code on Windows.7

Beyond compilers, build systems are essential for managing the entire compilation process, including linking libraries and generating executables.

* **MSBuild:** Microsoft's build platform, seamlessly integrated into Visual Studio.3  
* **CMake:** A powerful, cross-platform, open-source build system generator. Visual Studio offers native support for CMake projects, allowing direct editing, building, and debugging within the IDE.3 CMake relies on configuration files such as  
  CMakeLists.txt and CMakePresets.json to define the project structure and build rules.8

CMake is highly recommended for managing the complexity of this project and its external dependencies, such as OpenCV and a cryptography library. It provides a standardized, cross-platform approach that integrates effectively with Visual Studio, simplifying the overall dependency management process. This approach is particularly beneficial when dealing with multiple external libraries, as it abstracts away platform-specific build details and ensures a consistent build environment.

### **Integrating OpenCV for C++: A Step-by-Step Installation Guide**

OpenCV is a critical dependency for the face detection and recognition features of this project. Proper integration is essential for successful development.

**Prerequisites:** Visual Studio must be installed on the system prior to installing OpenCV.9

**Traditional Installation:** This method involves downloading a specific OpenCV installer (.exe file) that matches the installed Visual Studio version from official sources.9 After downloading, the executable is run to extract the OpenCV files to a chosen directory, such as

C:\\OpenCV.9 Manual configuration within Visual Studio is then required, which includes meticulously setting "Include Directories," "Library Directories," and "Additional Dependencies" in the project's properties. Often, post-build events must also be configured to copy necessary DLLs to the executable's output directory.10 This manual process can be prone to errors and is less efficient for complex projects.

**Recommended Installation (via vcpkg):** A more streamlined and modern approach involves using vcpkg, Microsoft's C++ package manager. The process begins by cloning the vcpkg repository from GitHub and executing its bootstrap script.12 Once

vcpkg is set up, OpenCV can be installed with a simple command, for example, vcpkg install opencv:x64-windows. vcpkg automates the entire process, including downloading, building, and integrating OpenCV with the Visual Studio/CMake project.12

Utilizing vcpkg for OpenCV installation offers significant advantages over manual methods. It streamlines dependency management, substantially reduces the likelihood of configuration errors, and ensures a more reproducible build environment across different development machines. This approach aligns with modern C++ development practices, enhancing efficiency and reliability for the project.

## **3\. Designing the Application Architecture**

### **Principles of Secure Desktop Application Design**

Software architecture serves as the fundamental blueprint for building software, illustrating how various components interoperate.1 Adhering to sound architectural principles is paramount for developing a secure and robust desktop application. Key benefits derived from a well-designed architecture include modularity, where the system is divided into interchangeable components that can be developed, tested, and maintained independently. Encapsulation is another critical principle, helping to conceal the internal details of components while exposing only necessary information, thereby reducing system complexity.1 These principles collectively contribute to improved scalability, flexibility, and maintainability of the application.

Beyond structural principles, general C++ coding practices are essential for ensuring robustness and security. This includes designing functions that primarily operate on their inputs, minimizing side effects, and creating distinct structs for different pieces of data to prevent type confusion. Adopting strict coding standards, avoiding namespace pollution, utilizing tools like clang-format, and enabling comprehensive compiler warnings are also crucial steps in identifying and mitigating potential issues early in the development cycle.13

### **Separation of Concerns: UI, Business Logic, Data, and Security Layers**

A layered architecture, often referred to as N-Tier architecture, is a widely adopted software design pattern that segregates application components into distinct layers, each with specialized responsibilities.1 This separation is vital for maintaining a clean, modular, and secure codebase.

* **Presentation Layer (UI):** This is the topmost layer, responsible for all user interaction and the display of information. It handles user input and renders the application's visual elements. In this project, the chosen UI framework (Qt) will reside within this layer.1  
* **Application/Business Logic Layer:** Situated beneath the Presentation Layer, this layer encapsulates the core business rules and logic of the application. It processes user requests, orchestrates operations such as facial authentication, and manages the overall flow of password management functionalities.1  
* **Data Access Layer:** This layer is responsible for abstracting the underlying data storage mechanisms. It handles the retrieval and storage of data, interacting directly with the encrypted password file. This separation ensures that changes in the data storage method do not impact the business logic or UI layers.1  
* **Security Layer (Cross-cutting concern):** While not a strictly vertical layer in the traditional sense, security is a pervasive concern that permeates all architectural layers. Cryptographic operations (hashing, encryption, key derivation, secure random number generation) and secure coding practices are fundamental to every component. This can be implemented as a dedicated security module that other layers consume, or as a set of rigorous practices applied across the codebase.

### **Inter-Module Communication Strategies**

Effective communication between different modules and layers is critical for a well-functioning application. In a pure layered architecture, communication typically flows downwards, meaning a layer should primarily interact only with the layer directly beneath it. This minimizes dependencies and simplifies the control structure.14

For the Presentation Layer, architectural patterns like **Model-View-Presenter (MVP)** and **Model-View-ViewModel (MVVM)** are highly suitable. These patterns promote a clean separation between the user interface and the underlying application logic.15

* **MVP:** This pattern separates the UI into three components: the **View** (responsible for rendering UI elements), the **Presenter** (which mediates between the View and the Model, handling UI actions and updating the View), and the **Model** (encapsulating business logic and data management).15 The Presenter communicates with the View through an interface, ensuring loose coupling and enhancing testability.15  
* **MVVM:** Similar to MVP, MVVM introduces a **ViewModel** that acts as an intermediary between the Model and the View. The ViewModel exposes data streams and commands that the View can bind to, often leveraging data binding mechanisms. A key advantage of MVVM is that the ViewModel does not hold a direct reference to the View, further enhancing testability and reusability of the presentation logic.15

Qt's powerful **Signal/Slot mechanism** is an ideal fit for implementing communication within MVP or MVVM patterns. This mechanism allows objects to communicate without tight coupling, as a signal emitted by one object can be connected to a slot (a function) in another object, regardless of their class hierarchy.19

A layered architecture combined with the Model-View-Presenter (MVP) or Model-View-ViewModel (MVVM) pattern is ideal for this project. This combination promotes modularity, testability, and maintainability, which are especially critical for a security-focused application. Without such patterns, UI code often becomes tightly coupled with business logic, leading to monolithic classes that are difficult to manage, test, and extend.16 By adopting MVP/MVVM, the UI is decoupled from the application's core logic, making it more testable and promoting clear separation of responsibilities. In a security-critical application, this clear separation helps prevent vulnerabilities from one layer (e.g., UI input errors) from impacting sensitive data handling in another layer, and also simplifies security audits.

## **4\. Implementing Secure Password Storage**

### **Foundations of Password Security: Hashing, Salting, and Key Stretching**

The secure storage of passwords is a cornerstone of any robust security system. This involves more than simple encryption; it requires a multi-layered approach incorporating hashing, salting, and key stretching.

**Password Hashing** is a one-way cryptographic function that transforms a password into a fixed-size string, known as a hash or digest.20 The critical property of a cryptographic hash function is that it is computationally infeasible to reverse the process and retrieve the original password from its hash. When a user attempts to log in, the entered password is hashed, and this newly generated hash is compared against the stored hash. If they match, access is granted.20 Fast cryptographic hash functions like MD5, SHA1, SHA256, and SHA512 are explicitly not recommended for direct password hashing due to their speed, which makes them vulnerable to brute-force attacks.20

**Salting** is a crucial technique that enhances the security of password hashing. A unique, cryptographically secure random value, known as a salt, is added to each password *before* it is hashed.20 This ensures that even if two users choose the exact same password, they will produce distinct hashes because of the unique salt appended to each. Salting effectively mitigates "rainbow table" attacks, which rely on precomputed hashes, and significantly slows down dictionary and brute-force attacks by forcing attackers to compute the hash individually for each user's password and its unique salt.20 The salt itself does not need to be kept secret and is typically stored alongside the hash.20

**Key Stretching**, implemented through Password-Based Key Derivation Functions (PBKDFs), further fortifies password security by making the hashing process computationally and/or memory-intensive. This deliberate slowness is designed to deter brute-force attacks by increasing the time and resources required to test each password guess.20

Several modern PBKDFs are recommended for password hashing:

* **Argon2:** This algorithm emerged as the winner of the Password Hashing Competition (PHC) and is currently considered the strongest password hashing algorithm available.22 Its strength lies in its "memory-hard" design, meaning it requires a significant amount of memory to compute. This characteristic makes it particularly difficult for attackers to leverage specialized hardware like GPUs and ASICs, which are optimized for parallel computation but often have limited dedicated memory, to crack passwords efficiently.22 Argon2 offers three variants: Argon2d, Argon2i, and Argon2id. Argon2id is the recommended variant for general use due to its hybrid approach, which is considered highly secure against both side-channel and parallel attacks.23  
* **bcrypt:** An older but still widely used and secure algorithm, bcrypt is designed to be computationally expensive, requiring significant processing power.22 It also has a work factor parameter that controls its computational cost.22  
* **scrypt:** Similar to bcrypt in its computational expense, scrypt also incorporates memory-hardness, akin to Argon2, making it resistant to certain types of hardware attacks.22  
* **PBKDF2:** This is a key derivation function designed to be computationally expensive, often used in conjunction with strong hash functions like SHA-256 or SHA-512.22 The OWASP guidelines recommend a high iteration count (e.g., 600,000 iterations) for PBKDF2 to ensure adequate security against brute-force attacks.22

Argon2id is the strongest recommended password hashing algorithm for this project. Its superior resistance against modern brute-force and side-channel attacks makes it the most secure choice for protecting the master password. The evolution of hashing algorithms demonstrates a clear shift towards memory-hard functions to counteract the increasing power of cracking hardware. While bcrypt and scrypt remain secure options, Argon2id represents the current state-of-the-art, offering the highest level of protection for the most critical credential in the system.

**Table 1: Comparison of Recommended Password Hashing Algorithms**

| Algorithm Name | Key Properties | Security Level | Resistance to Attacks (Primary) | Current Recommendation for New Development |
| :---- | :---- | :---- | :---- | :---- |
| **Argon2id** | Memory-hard, CPU-intensive, Tunable (M, t, p) | Strongest | GPU/ASIC, Rainbow Table, Brute-force | Highly Recommended |
| **bcrypt** | CPU-intensive, Moderate memory-hard | Secure | Rainbow Table, Brute-force | Recommended |
| **scrypt** | Memory-hard, CPU-intensive, Tunable | Secure | GPU/ASIC, Rainbow Table, Brute-force | Recommended |
| **PBKDF2** | CPU-intensive, Iteration-based | Older but still secure | Rainbow Table, Dictionary (less against GPU) | Acceptable with high iterations |

### **Encryption of Sensitive Data: AES with PBKDF2 for Key Derivation**

Beyond hashing the master password, the actual stored passwords must be encrypted to ensure their confidentiality. Symmetric encryption algorithms are ideal for this purpose, as they use a single key for both encryption and decryption.25

The **Advanced Encryption Standard (AES)** is the U.S. government standard for symmetric encryption and is widely regarded as highly trusted and secure.26 AES supports key sizes of 128, 192, and 256 bits, with larger key sizes offering stronger security.28 For this project, AES-256 is a robust choice for encrypting the password data file.

Directly using a user's chosen password as an encryption key is inherently insecure due to the common weakness and predictability of user-generated passwords. Instead, a **Password-Based Key Derivation Function (PBKDF)** is employed to "stretch" the password into a cryptographically strong, fixed-length encryption key.24

**PBKDF2** is a suitable choice for this task. It takes the user's password, a unique salt, a high iteration count, and a hash function (e.g., SHA256) to produce the derived key.24 The high iteration count makes the key derivation process computationally expensive, significantly slowing down any attempts at brute-forcing the derived key.

For block ciphers like AES, especially when operating in modes such as Cipher Block Chaining (CBC) or Galois/Counter Mode (GCM), an **Initialization Vector (IV)** is required. The IV must be unique for each encryption operation (e.g., for each password entry or file encryption) to ensure that identical plaintext blocks encrypt to different ciphertext blocks.26 The IV does not need to be kept secret and can be stored alongside the ciphertext.26

The **Crypto++ library** is a robust C++ cryptographic library that provides well-vetted implementations for AES, PBKDF2, and secure random number generation.32 It offers examples demonstrating AES encryption with PBKDF2 key derivation and proper IV handling.32

The master password should be used to derive an encryption key via PBKDF2, which then encrypts the password data file using AES. The unique salt used for PBKDF2 and the Initialization Vector (IV) for AES must be generated using a Cryptographically Secure Random Number Generator (CSRNG) and stored alongside the ciphertext for successful decryption. This approach addresses the inherent weakness of directly using user-chosen passwords as encryption keys. PBKDF2 stretches the password into a strong key, while the salt ensures uniqueness and prevents pre-computation attacks. The IV is crucial for ensuring ciphertext diversity. Both the salt and IV must be generated unpredictably using a CSRNG to prevent any compromise of the derived key or ciphertext. Storing these components with the encrypted data is necessary for successful decryption. This multi-layered cryptographic approach significantly enhances the security of the stored passwords.

**Table 2: AES Encryption Modes and Their Suitability**

| Mode Name | Properties | Padding Requirement | IV Requirement | Use Cases | Suitability for Password Manager (File Encryption) |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **CBC** | Block Cipher, Confidentiality | Yes | Yes (unique) | General purpose, block-by-block encryption | Good, but lacks integrity check |
| **CTR** | Stream Cipher, Confidentiality | No | Yes (unique) | Streaming data, parallelizable | Good, but lacks integrity check |
| **GCM** | Authenticated Encryption (Confidentiality \+ Integrity), Stream Cipher | No | Yes (unique) | Authenticated data, high performance | **Highly Recommended (provides data integrity)** |

For sensitive data like passwords, ensuring data integrity (that the data has not been tampered with) is as crucial as confidentiality. Modes like GCM provide authenticated encryption, which means they not only encrypt the data but also generate a tag that can be used to verify if the ciphertext has been altered. This is a modern best practice for protecting sensitive information.

### **Secure File I/O: Encrypting and Decrypting Password Files**

File input/output operations for encrypted data require careful handling to prevent data corruption and ensure security. C++ provides fstream classes (ifstream, ofstream) for basic file operations.5 When dealing with binary encrypted data, it is imperative to open files in binary mode to prevent unintended character conversions that can corrupt the ciphertext.

The Crypto++ library offers specialized FileSource and FileSink classes that integrate seamlessly with its pipeline architecture, facilitating secure reading from and writing to files.38 This allows for direct streaming of file data through cryptographic filters, such as AES encryption/decryption, without intermediate buffering that could expose sensitive information.

The encrypted password data, along with its unique salt and Initialization Vector (IV), should be stored together in a structured binary format within a single file. This approach ensures data integrity, simplifies retrieval, and minimizes the risk of irrecoverable data due to missing components. As both the salt (for key derivation) and the IV (for AES decryption) are absolutely necessary for decryption, bundling them with the encrypted data into a single, well-defined binary file ensures that all required components are always present and correctly associated. Storing these components separately or in an unstructured manner introduces significant risks, such as accidental deletion or synchronization issues, which could render the encrypted data permanently inaccessible. The salt and IV can be stored as raw bytes or hex-encoded strings within a header section of the file, followed by the encrypted payload. This method simplifies file management for the application and enhances the reliability of data retrieval, directly contributing to the secure storage requirement.

### **Robust Key Management: Generating and Protecting Encryption Keys and Salts**

Effective key management is critical for the overall security of the password manager. This encompasses the secure generation, storage, and handling of cryptographic keys and salts throughout their lifecycle.

**Cryptographically Secure Random Number Generators (CSRNGs)** are indispensable for generating unpredictable keys, salts, and IVs.27 Randomness is a primitive for cryptographic operations, and predictable random numbers can lead to severe vulnerabilities. Crypto++ provides

AutoSeededRandomPool and OS\_GenerateRandomBlock for this purpose, which leverage the operating system's underlying entropy sources (e.g., CryptGenRandom on Windows) to produce high-quality random data.32

Key lifecycle management involves the creation, distribution, storage, rotation, and secure disposal of keys.27 For a desktop application, the primary focus is on secure generation, protecting keys at rest (through encryption), and handling them securely in memory.

Sensitive data, such as derived encryption keys and plaintext passwords, should never linger in memory longer than necessary. Standard C++ containers like std::string or std::vector\<char\> do not guarantee that their memory will be wiped upon deallocation, potentially leaving sensitive information vulnerable to memory dumps or swap file analysis. The Crypto++ library addresses this by providing SecByteBlock, a specialized class for handling sensitive byte arrays.32

SecByteBlock is designed to automatically overwrite its memory with zeros (or other patterns) upon destruction, preventing sensitive data from being recovered from residual memory. This practice significantly reduces the attack surface for sensitive data, moving beyond just disk encryption to encompass in-memory protection, which is crucial for a real-world security application. Beyond using secure containers, minimizing the lifetime of sensitive data in memory is a best practice. For instance, a password should only be decrypted when it is actively needed for autofill or copying, used immediately, and then its memory cleared or re-encrypted. This aligns with broader secure C++ coding guidelines that advocate for avoiding raw pointers and utilizing smart containers for enhanced memory management and security.40

## **5\. Integrating Face Detection and Recognition with OpenCV**

### **Webcam Access and Live Stream Processing: Capturing Frames for Analysis**

The foundation of face detection and recognition in this project is the ability to access and process live video streams from a webcam. OpenCV provides the necessary tools for this functionality.

OpenCV's cv::VideoCapture class serves as the primary interface for accessing webcam feeds in C++.42 To open the default webcam, an instance of

cv::VideoCapture is initialized with an index of 0 (e.g., cv::VideoCapture camera(0);).43 The

isOpened() method can be used to verify successful camera initialization.43

Once the camera is open, video frames are continuously captured within an infinite loop. The camera \>\> frame; operator is used to grab the next frame from the camera and store it in a cv::Mat object.43 To display the live video feed,

cv::imshow("Webcam", frame); is employed, which renders the cv::Mat frame in a named window.43 A call to

cv::waitKey(delay) is crucial within the loop; it introduces a delay (in milliseconds) to control the frame rate and also captures keyboard input, allowing for user interaction such as pressing 'Esc' to exit the application.43 This continuous capture and display loop forms the basis for real-time face processing.

### **Face Detection Algorithms: Haar Cascades vs. Modern DNN Models (e.g., YuNet)**

Face detection is the initial step in the biometric authentication process, locating human faces within a video frame. OpenCV offers several algorithms for this task.

**Haar Cascades** represent a machine learning-based approach that utilizes pre-trained XML classifiers, such as haarcascade\_frontalface\_alt2.xml, to detect objects like faces.42 The

cv::CascadeClassifier class is used to load these classifiers and apply them to an image.42 The

detectMultiScale(image, objects, scaleFactor, minNeighbors, minSize) method performs the detection, returning a vector of bounding boxes (Rect objects) around the detected faces.42 Haar Cascades are relatively fast and can operate in real-time, making them simple to implement.47 However, their primary drawbacks include a propensity for false positives and lower accuracy compared to modern deep learning techniques, making them less ideal for security-critical applications.47

**Modern DNN Models**, such as YuNet, represent a significant advancement in face detection. OpenCV has integrated these deep neural network models into its library.45 YuNet is particularly noted for being a "very accurate model while still being lightweight to run at real-time speeds on CPU".45 The

cv::FaceDetectorYN module is optimized for real-time applications and is capable of detecting multiple faces simultaneously with robust performance.53

For a password manager, the face detection component is an integral part of the security mechanism. False positives (incorrectly identifying a non-face as a face) can lead to usability issues or potential security bypasses, while false negatives (failing to detect a legitimate face) can cause user frustration. YuNet is the preferred face detection algorithm for this project due to its superior accuracy and real-time performance on typical CPUs. This offers a more robust and reliable user experience compared to Haar Cascades, which are more prone to false positives. The quality of the AI model is paramount for security, and newer, more accurate models like YuNet should be prioritized.

**Table 3: Face Detection Algorithm Comparison**

| Algorithm Name | Approach | Accuracy | Speed/Real-time (CPU) | False Positive Rate | Ease of Implementation | Suitability for Security Application |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **Haar Cascade** | Feature-based (Viola-Jones) | General | Fast | High | Simple | Less suitable (due to false positives) |
| **YuNet** | Deep Learning | High | Optimized for real-time | Low | Moderate | Highly suitable |

### **Face Recognition for Authentication: Choosing and Implementing a Model**

The project requires not merely detecting a face but recognizing *who* the person is to grant access. This distinction between face detection and face recognition is crucial for the authentication mechanism. Face detection merely locates faces in an image 42, while face recognition identifies a specific individual by comparing detected faces against a database of known individuals.54 For a password manager, true face

*recognition* (identifying a specific user) is necessary for secure access, not just *detection* (confirming a face is present). This implies a multi-step process: initial user enrollment (training the recognition model) and subsequent authentication (recognizing the user's face). Without recognition, anyone (or even a photo) could potentially gain access, rendering the security feature ineffective.

OpenCV provides the FaceRecognizer class, which includes algorithms like Eigenfaces, Fisherfaces, and Local Binary Patterns Histograms (LBPH).54

* **LBPH (Local Binary Patterns Histograms):** This algorithm is noted for its balance of performance and simplicity, and its ability to recognize faces from various angles (front and side).55 The recognition process typically involves three phases:  
  1. **Data Collection:** This phase requires extracting faces from a dataset of images belonging to the authorized user(s) and labeling them with unique IDs (e.g., 0 for User A, 1 for User B).54  
  2. **Training:** The LBPHFaceRecognizer model is trained using these collected face samples and their corresponding IDs (e.g., model-\>train(faceSamples, faceIds)).55 This step builds the internal representation of the known faces.  
  3. **Recognition (Prediction):** During authentication, a new face is captured and processed. The trained model then predicts the predictedLabel (user ID) and a confidence score (e.g., model-\>predict(face, predictedLabel, confidence)).55 A low confidence score indicates a strong match, while a high score suggests a weak or no match.  
* **DNN-based Face Recognition:** More advanced and accurate face recognition systems often leverage deep learning techniques, building upon the capabilities of DNN face detectors like YuNet.53 These models typically involve extracting high-dimensional feature vectors (embeddings) from faces and then comparing these vectors using distance metrics (e.g., cosine similarity) to determine identity.

For security-critical applications, face recognition accuracy is evaluated using metrics such as True Acceptance Rate (TAR) at very low False Acceptance Rates (FAR), and False Non-Match Rate (FNMR) at low False Match Rates (FMR).58 Independent evaluations, like those conducted by NIST, provide benchmarks for these algorithms.59

The project must extend beyond simple face detection to a full face recognition pipeline, including user enrollment and model training, to fulfill the "securely stores and manages" and "face unlock" requirements. This ensures that the system identifies *who* is attempting access, not just *that* a face is present.

**Table 4: Face Recognition Algorithm Comparison (for Authentication)**

| Algorithm Name | Approach | Training Data Requirements | Accuracy (General) | Robustness (Pose, Lighting) | Speed (Real-time) | Suitability for Authentication |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| **LBPH** | Local Feature | Moderate (labeled images) | Good | Moderate | Fast | Good starting point for simple cases |
| **Eigenfaces** | Holistic (PCA) | Moderate | Moderate | Sensitive | Fast | Less common for modern systems |
| **Fisherfaces** | Holistic (LDA) | Moderate | Good | Moderate | Fast | Less common for modern systems |
| **DNN-based** | Deep Learning | Large (diverse, labeled) | Very High | High | Moderate to Fast | Highly suitable for robust security |

### **Performance Considerations for Real-time Face Processing**

Achieving smooth, real-time face processing is crucial for a positive user experience and effective security. Several factors influence performance:

* **Optimization:** Converting captured frames to grayscale is a common optimization, as many face detection and recognition algorithms (like Haar Cascades and LBPH) operate on grayscale images, reducing processing overhead.47  
* **Frame Rate:** The processing pipeline (image capture, detection, and recognition) must be optimized to keep pace with the webcam's frame rate. If processing takes longer than the interval between frames, frames will be dropped, leading to a choppy or unresponsive experience.56  
* **Parameter Tuning:** For algorithms like Haar Cascades, parameters such as scaleFactor, minNeighbors, and minSize in detectMultiScale can be tuned to balance detection speed and accuracy for the specific operating environment.47 Optimal tuning can reduce false positives and improve overall efficiency.  
* **Multithreading:** To prevent the UI from freezing during intensive image processing, it is crucial to perform image capture, face detection, and recognition in a separate thread from the main UI thread.60 This ensures that the user interface remains responsive while the computationally heavy tasks are executed in the background.

## **6\. Developing the User Interface**

### **UI Framework Selection: In-depth Comparison of Qt, SFML, and Console**

The user interface is the primary point of interaction for the password manager. The choice of UI framework significantly impacts development complexity, application features, and user experience. The user specified Qt, SFML, or Console as options.

* Qt:  
  Qt is a comprehensive C++ framework designed for building cross-platform applications, including rich desktop graphical user interfaces.61 It offers two primary approaches for UI development:  
  * **Widgets:** A traditional C++-based approach providing a rich set of pre-built UI components like buttons, text boxes, tables, and layouts, ideal for complex desktop applications.61 Qt Designer can be used to visually design these interfaces, generating  
    .ui files that are transformed into C++ header files, simplifying UI creation.62  
  * **QML:** A declarative language (similar to JavaScript) for creating modern, fluid, and animated user interfaces, particularly suitable for touch-enabled or visually rich applications.63 QML integrates seamlessly with C++ code, allowing C++ logic to be exposed to the QML UI.63

    Qt provides native multimedia modules (QtMultimedia) with classes like QCamera and QImageCapture for direct webcam integration, simplifying the display of live video streams within the UI.64 It is highly compatible with modern C++ features, RAII (Resource Acquisition Is Initialization), and the Standard Template Library (STL).61 Qt boasts extensive documentation, a large and active community, and professional development tools like Qt Creator and Qt Designer.61 Crucially, Qt offers well-documented methods for converting  
    cv::Mat (OpenCV image format) to QImage (Qt image format) for display in UI elements such as QLabel.60  
* SFML (Simple and Fast Multimedia Library):  
  SFML is a lightweight C++ multimedia library primarily focused on hardware-accelerated 2D graphics, audio, and networking.61 It provides basic windowing capabilities (  
  sf::RenderWindow) and event handling.67 While SFML is excellent for game development or simple graphical applications, it is not a full-fledged UI framework. It lacks built-in UI widgets (e.g., buttons, text input fields, scrollable lists) that are necessary for a complex application like a password manager.67 Implementing these UI elements from scratch in SFML would require significant custom development. Integrating webcam feeds involves converting OpenCV  
  cv::Mat frames to sf::Image and then to sf::Texture for display via sf::Sprite.68  
* Console:  
  A console application relies solely on text-based input and output in a command-line interface. This option is fundamentally unsuitable for a password manager that requires face detection. It cannot display real-time video streams, nor can it provide the graphical, interactive interface necessary for managing multiple password entries and a user-friendly experience. This option is immediately dismissed for practical reasons.

Qt is the unequivocally superior choice for this Windows desktop application. Its comprehensive features, robust UI capabilities, and native support for multimedia (including cameras) greatly simplify the integration of complex components like OpenCV and provide a professional user experience. A password manager with face detection inherently requires a graphical interface; therefore, a console application is inadequate. SFML, while capable of graphics, is not a UI framework, and building a complete UI with it would be a massive and inefficient undertaking. Qt, conversely, provides a complete, efficient, and professional solution that aligns perfectly with the project's scope and the goal of gaining hands-on experience with a robust system.

**Table 5: Comparison of UI Frameworks (Qt, SFML, Console)**

| Feature / Framework | Qt | SFML | Console |
| :---- | :---- | :---- | :---- |
| **Type** | Comprehensive Application Framework | Multimedia Library (Graphics, Audio, Network) | Text-based Interface |
| **UI Components** | Rich Widgets, Declarative QML | None (requires custom implementation) | Command-line I/O only |
| **Webcam Integration** | Native QtMultimedia module (QCamera) | Requires OpenCV \+ manual cv::Mat conversion | Not possible |
| **OpenCV Integration** | cv::Mat to QImage conversion | cv::Mat to sf::Image/sf::Texture conversion | Not applicable |
| **Complexity for UI** | Moderate (with Designer/QML) | High (for full UI) | Very Low |
| **Target Use Case** | Complex desktop apps, cross-platform GUIs | Games, multimedia applications | Simple scripts, command-line tools |
| **Suitability for Project** | **Highly Recommended** (Professional UI, easy integration) | Not Recommended (lacks UI widgets) | Not Suitable (no graphical capabilities) |

### **Displaying OpenCV Frames in the UI: Techniques for Integration**

Once Qt is selected as the UI framework, a crucial step is to efficiently display the live video frames captured by OpenCV within the Qt application. OpenCV's cv::Mat is the standard data structure for images and frames, while Qt's UI elements typically work with QImage or QPixmap.

The primary technique involves converting the cv::Mat frame into a QImage object. This conversion typically requires handling different image formats (e.g., grayscale, BGR, RGB) and ensuring correct memory management. For color images, a conversion from OpenCV's default BGR format to Qt's RGB format is often necessary.60 Once a

QImage is obtained, it can be easily converted to a QPixmap and then displayed in a QLabel or a custom QWidget.60

To maintain UI responsiveness, especially when dealing with high-resolution or high-frame-rate video, it is essential to perform the OpenCV frame capture and processing in a separate thread from the main UI thread.60 The processing thread can then emit a signal containing the processed

QImage or QPixmap when a new frame is ready. The UI thread, in turn, connects to this signal and updates the display element, ensuring that the UI remains fluid and does not freeze during intensive image processing.60 This asynchronous approach is a best practice for integrating computationally intensive tasks with graphical user interfaces.

### **UI/UX Best Practices for a Secure Password Manager**

Designing the user interface for a security-critical application like a password manager requires adherence to specific UI/UX best practices to enhance both usability and security.

* **Clear Feedback:** Provide immediate and clear feedback to the user regarding the status of operations, especially during face detection/recognition and password access. This includes visual cues (e.g., "Scanning face...", "Access Granted/Denied") and error messages.  
* **Intuitive Navigation:** The interface should be intuitive and easy to navigate, allowing users to quickly find and manage their passwords without confusion.  
* **Minimalist Design:** Avoid clutter and unnecessary elements. A clean, minimalist design reduces cognitive load and helps users focus on the core functionality.  
* **Secure Input Handling:** For password input fields, implement standard security measures such as masking characters. For face-based authentication, ensure the webcam feed is clearly visible to the user during the process.  
* **Error Handling and Messaging:** Display user-friendly error messages that guide the user on how to resolve issues (e.g., "Face not recognized, please try again," "Password file corrupted"). Avoid revealing sensitive internal error details that could aid attackers.69  
* **Responsiveness:** Ensure the UI remains responsive, even during background operations like encryption/decryption or complex image processing. As discussed, multithreading is key to achieving this.60  
* **Accessibility:** Consider accessibility features for users with disabilities, such as keyboard navigation and screen reader compatibility.  
* **Visual Consistency:** Maintain a consistent visual style and layout throughout the application for a cohesive user experience. Qt's layout managers and styling capabilities can assist with this.63

## **7\. Ensuring Application Security and Robustness**

### **Secure Coding Practices: Preventing Common Vulnerabilities**

Writing secure C++ code is paramount for a password manager. C++ offers powerful low-level memory management, but this also introduces potential vulnerabilities if not handled carefully.

* **Input Validation:** All user inputs must be rigorously validated and sanitized to prevent injection attacks and other forms of malicious input.69 This means checking inputs for expected types, values, and lengths. Server-side validation (or internal validation for a desktop app) is crucial, stripping harmful components from user inputs.70  
* **Buffer Overflows:** These are a significant source of security issues in C++.40 Developers must be aware of risky functions and avoid them. For instance, instead of  
  strcpy(), use safer bounded functions like strncpy() or strlcpy(), which allow specifying buffer limits.41 Similarly, avoid  
  gets() and prefer fgets() for bounded input.41 Modern C++ features like  
  std::string automatically manage memory and eliminate many buffer overflow risks.41 Compiler protections such as  
  \-fstack-protector-strong and AddressSanitizer (-fsanitize=address) can detect and mitigate buffer overflows at compile-time and runtime.41  
* **Injection Attacks:** While often associated with web applications (e.g., SQL Injection), the principle applies to any scenario where user-supplied data might be interpreted as executable code. Input validation and using prepared statements (or equivalent parameterized queries for local data storage) are the most important measures.70 This separates code logic from user inputs, treating inputs purely as data.70  
* **Avoid Homegrown Cryptography:** Unless one is an expert security researcher, implementing custom cryptographic functions is strongly discouraged. Rely on well-known, peer-reviewed cryptographic libraries like Crypto++ or OpenSSL, ensuring they have no known breaches or compromises.20  
* **Type Safety and Undefined Behavior:** Leverage C++'s type system and avoid intentionally bypassing type checking.69 Undefined behavior in C++ can lead to unpredictable and potentially exploitable program states. Compilers with flags like  
  \-fsanitize=undefined can help detect such issues.69  
* **Principle of Least Privilege:** The application should operate with the minimum necessary privileges required to perform its functions. If elevated privileges are needed, they should be acquired as late as possible and dropped as soon as they are no longer required.74

### **Memory Management: Handling Sensitive Data in C++**

Careful memory management is critical in C++ to prevent vulnerabilities like memory leaks and to secure sensitive data.

* **Smart Pointers and RAII:** Modern C++ best practices advocate for the use of smart pointers (std::unique\_ptr, std::shared\_ptr) instead of raw pointers (T\*) for managing dynamically allocated memory.40 These smart pointers automatically handle memory deallocation when they go out of scope, adhering to the Resource Acquisition Is Initialization (RAII) idiom and preventing memory leaks.41  
* **Standard Containers:** Prefer std::string, std::vector, and std::array over C-style arrays and strings. These containers manage their own memory, provide bounds checking (e.g., via .at() method), and reduce the risk of buffer overflows.40  
* **Secure Memory Wiping:** As discussed in Section 4.4, for highly sensitive data like derived encryption keys or plaintext passwords, standard containers are insufficient as they do not guarantee memory wiping upon destruction. Using specialized classes like Crypto++'s SecByteBlock ensures that memory holding sensitive data is overwritten with zeros upon deallocation, preventing data remnants from being recovered.32 The lifetime of such sensitive data in memory should be minimized.

### **Error Handling and Exception Management**

Robust error and exception handling are vital for application stability and security. Unhandled errors or exceptions can lead to crashes, inconsistent states, or the leakage of sensitive information.

* **Anticipate Errors:** Design the application to anticipate and gracefully handle potential errors and exceptions, rather than assuming a "happy path".69  
* **Prevent Information Leakage:** Error messages and exception details should not expose sensitive information such as stack traces, database dumps, internal error codes, or user IDs.69 Such information can be exploited by attackers to gain insights into the system's internal workings.  
* **Fail Securely:** Ensure that error conditions do not inadvertently lead to a "fail-open" scenario where security mechanisms are bypassed. For instance, an exception during authentication should not grant access.69  
* **Handle, Don't Just Catch:** Simply catching an exception and ignoring it ("swallowing an exception") can leave the system in an inconsistent and vulnerable state.69 Errors must be handled appropriately, either by retrying, logging, or gracefully terminating the operation.

## **8\. Testing and Quality Assurance**

Thorough testing is indispensable for ensuring the functionality, security, and usability of the password manager. Various testing strategies must be employed across different levels of the application.

### **Unit Testing: Verifying Individual Components**

Unit testing focuses on verifying the correctness of individual components or functions in isolation.75 For this project, unit tests would target:

* **Cryptographic Functions:** Verify that hashing, key derivation (PBKDF2), and encryption/decryption (AES) functions produce expected outputs for given inputs. Test vectors provided by cryptographic standards (e.g., NIST) can be leveraged for algorithm validation.77  
* **Image Processing Modules:** Test individual OpenCV functions for face detection (e.g., detectMultiScale with various images) and face recognition (e.g., predict with known and unknown faces).  
* **File Handling:** Verify that data is correctly written to and read from encrypted files.  
* **Core Logic:** Test business rules and data manipulation logic independently of the UI.

Visual Studio includes several C++ unit testing frameworks, such as the Microsoft Unit Testing Framework for C++, Google Test, and Boost.Test.75 These frameworks integrate with the Test Explorer window in Visual Studio, allowing developers to write and run tests efficiently.75

### **Integration Testing: Ensuring Seamless Interaction Between Modules**

Integration testing focuses on verifying the interactions and interfaces between different modules and components of the application.76 For the password manager, this would involve:

* **UI-to-Logic Flow:** Testing that UI actions correctly trigger business logic and that results are accurately displayed back in the UI.  
* **Face Recognition to Password Access:** Verifying that successful face recognition correctly triggers access to encrypted passwords.  
* **Encryption/Decryption Pipeline:** Ensuring that the entire process of encrypting password data, storing it, retrieving it, and decrypting it functions flawlessly. This includes simulating scenarios like partial data transmission or corrupted ciphertext to test error handling.77

### **Security Testing: Validating Encryption Integrity and Vulnerability Assessment**

Security testing is a specialized area that aims to identify vulnerabilities and weaknesses in the application's security mechanisms.

* **Encryption Integrity Testing:** This involves validating that encryption algorithms are working correctly in both directions (encryption and decryption) and that data integrity is maintained. Techniques include using test vectors (predefined inputs and outputs) from cryptographic standards to verify algorithm correctness.77 Key management testing is also crucial, simulating key rotation and expiration scenarios and verifying that keys are securely stored (e.g., not hardcoded).77  
* **Vulnerability Assessment:** Conduct application penetration testing to identify common threats such as Man-in-the-Middle (MITM) attacks in encrypted communications, padding oracle attacks, or weak key generation.77 Tools like OWASP ZAP can be used to simulate attacks.77  
* **Secure Coding Practices Review:** Static analysis tools (like cppcheck or Clang-tidy) and dynamic analysis tools (like Valgrind for memory issues) can be used to identify potential security flaws, buffer overflows, and memory leaks.40

### **UI Responsiveness and Usability Testing**

UI responsiveness and usability are critical for user satisfaction, especially in an application used frequently.

* **Responsiveness Testing:** This assesses how the UI performs under various conditions, particularly when computationally intensive tasks (like face processing) are running. Multithreading is key to ensuring the UI remains fluid.60 Automated GUI testing tools can help verify that the UI does not freeze or become unresponsive.79  
* **Usability Testing:** This involves evaluating the application's ease of use, learnability, and user satisfaction through user feedback. For the face unlock feature, this means assessing the user's experience with the webcam interaction, feedback messages, and overall flow.  
* **Automated UI Testing:** While some advanced UI testing features (like Coded UI Tests) are not directly supported for C++ in Visual Studio, frameworks like Qt Test provide functionality for mouse and keyboard simulation, allowing for automated testing of graphical user interfaces.75 This can help ensure that UI elements are correctly rendered and respond as expected without laborious manual testing.79

## **9\. Deployment and Distribution**

Deploying a C++ Windows desktop application involves packaging the executable and its dependencies into an installable format, and ensuring its trustworthiness through digital signing.

### **Packaging the Windows Desktop Application (MSI Installer)**

For Windows desktop applications, an MSI (Microsoft Installer) package is a standard and professional way to distribute software. Visual Studio provides built-in capabilities for creating MSI installers.

* **Visual Studio Installer Projects:** This extension for Visual Studio adds "Setup Project" templates, allowing developers to create basic installers directly within the IDE.81 The process involves adding the project's primary output (the executable and its associated files), creating shortcuts (e.g., on the desktop or in the Start Menu), and configuring launch conditions (e.g., requiring a specific Windows version) or prerequisites (e.g.,.NET Runtime).81  
* **Advanced Installer Extension:** For more advanced customization and features, the Advanced Installer for Visual Studio extension can be used. It provides a more comprehensive set of tools for packaging, including a visual editor for product details and advanced options.81

The generated setup.exe and setup.msi files can then be distributed to users, simplifying the installation process and ensuring all necessary files are correctly placed on the target system.82

### **Managing External Dependencies (OpenCV, Crypto++)**

A C++ application often relies on external libraries, which must be properly managed during deployment.

* **Dynamic vs. Static Linking:** Libraries can be linked dynamically (DLLs on Windows) or statically. Dynamic linking requires distributing the library's DLLs alongside the application executable, typically in the same folder.83 Static linking embeds the library code directly into the executable, resulting in a larger executable but no external DLL dependencies. For this project, dynamic linking is more common for large libraries like OpenCV and Qt.  
* **Qt Deployment Tool (windeployqt):** If Qt is used for the UI, Qt provides a utility called windeployqt. This tool automatically copies all necessary Qt DLLs and other dependencies into the application's deployment folder, simplifying the distribution process for Qt-based applications on Windows.83  
* **OpenCV and Crypto++ DLLs:** Similar to Qt, if OpenCV and Crypto++ are linked dynamically, their respective DLLs must be included in the deployment package. vcpkg (as recommended for installation) can assist in managing these dependencies by providing the necessary build artifacts.  
* **Dependency Management Best Practices:** It is common practice to place third-party build dependencies in a designated folder (e.g., third\_party) within the project repository. Build systems like CMake use target\_include\_directories to configure paths to these libraries, ensuring consistent dependency resolution across different build environments.84

### **Digitally Signing Your Application for Trust**

Digitally signing the application executable and installer is a critical step for establishing trust and ensuring the integrity of the distributed software.

* **Authenticode Technology:** Windows applications are typically signed using Authenticode technology, which involves signing files with a public/private key pair from a code signing certificate.85 This signature allows users to verify the publisher of the software and ensures that the file has not been tampered with since it was signed.87  
* **Code Signing Certificates:** These certificates are issued by trusted third-party Certificate Authorities (CAs).86 As of recent changes (e.g., June 1, 2023), private keys for code signing certificates often need to be stored on hardware security modules (HSMs) for enhanced security.85  
* **SignTool.exe:** This is a command-line tool provided with the Windows Software Development Kit (SDK) and automatically installed with Visual Studio.87  
  SignTool.exe is used to digitally sign files, verify signatures, and time-stamp files.87 The  
  sign command requires specifying the file digest algorithm (e.g., /fd SHA256) and a time stamp server URL (e.g., /td SHA256 /t http://timestamp.digicert.com) to ensure the signature remains valid even after the certificate expires.86  
* **Visual Studio Integration:** Visual Studio also provides options to sign application and deployment manifests directly within the project properties, typically for ClickOnce deployments, using a certificate from the Windows certificate store or a key file (.pfx).86

Digitally signing the application is crucial for gaining user trust and avoiding security warnings (e.g., Windows SmartScreen warnings) when users attempt to install or run the application.85 It provides an assurance of authenticity and integrity, which is particularly important for a security-focused password manager.

## **Conclusion and Future Enhancements**

This report has provided a comprehensive guide for building a secure C++ password manager with an integrated face detection and recognition system for Windows desktop environments. The recommended approach emphasizes a robust technology stack, including Visual Studio, CMake, and vcpkg for efficient development and dependency management. For core security, Argon2id is advocated for master password hashing, complemented by AES-GCM encryption with PBKDF2 key derivation and CSRNG-generated salts and IVs for sensitive data storage. The face unlock mechanism leverages OpenCV's YuNet for accurate real-time face detection and LBPH for user recognition. Qt is identified as the optimal UI framework, offering comprehensive features and seamless integration with OpenCV.

The architectural design prioritizes a layered approach combined with MVP/MVVM patterns to ensure modularity, testability, and maintainability, which are critical for a security-sensitive application. Secure coding practices, including stringent input validation, careful memory management with secure byte blocks, and robust error handling, are highlighted to mitigate common vulnerabilities. The importance of thorough unit, integration, and security testing, along with professional deployment practices like MSI installers and digital signing, has been underscored to deliver a reliable and trustworthy application.

### **Potential Areas for Future Development**

While the outlined project delivers a strong foundation, several enhancements could further improve its functionality and security:

* **Multi-Factor Authentication (MFA):** Integrating additional authentication factors beyond face recognition (e.g., a secondary PIN, a hardware token, or a mobile authenticator app) would significantly enhance security, providing defense in depth.  
* **Cloud Synchronization with End-to-End Encryption:** For user convenience, implementing secure synchronization of encrypted password data across multiple devices via cloud storage (e.g., Dropbox, Google Drive) would be valuable. This would require careful design to ensure end-to-end encryption, where data remains encrypted on the cloud server and is only decrypted locally on the user's trusted devices.  
* **Advanced Face Recognition Models:** Exploring and integrating more advanced deep learning-based face recognition models (e.g., FaceNet, ArcFace) that offer even higher accuracy and robustness against variations in pose, lighting, and expression could further strengthen the biometric authentication. These models often require larger training datasets and more computational resources but can provide superior performance in challenging real-world scenarios.  
* **Hardware Security Module (HSM) Integration:** For enterprise-grade security, integrating with a local or cloud-based HSM for master key storage and cryptographic operations could provide tamper-resistant protection for the most critical cryptographic assets.  
* **Cross-Platform Support:** While currently focused on Windows, extending the application to other platforms like macOS or Linux using Qt's cross-platform capabilities would broaden its usability.  
* **Password Generation and Strength Meter:** Adding a robust password generator and a real-time password strength meter would assist users in creating and managing stronger passwords.

#### **Works cited**

1. Types of Software Architecture Patterns \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/software-engineering/types-of-software-architecture-patterns/](https://www.geeksforgeeks.org/software-engineering/types-of-software-architecture-patterns/)  
2. Software Architectural Patterns in System Design \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/system-design/design-patterns-architecture/](https://www.geeksforgeeks.org/system-design/design-patterns-architecture/)  
3. Visual Studio C/C++ IDE and Compiler for Windows \- Microsoft, accessed on July 19, 2025, [https://visualstudio.microsoft.com/vs/features/cplusplus/](https://visualstudio.microsoft.com/vs/features/cplusplus/)  
4. Install C and C++ support in Visual Studio | Microsoft Learn, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170](https://learn.microsoft.com/en-us/cpp/build/vscpp-step-0-installation?view=msvc-170)  
5. Setting up C++ Development Environment \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/cpp/setting-c-development-environment/](https://www.geeksforgeeks.org/cpp/setting-c-development-environment/)  
6. Visual Studio Code on Windows, accessed on July 19, 2025, [https://code.visualstudio.com/docs/setup/windows](https://code.visualstudio.com/docs/setup/windows)  
7. Using GCC with MinGW \- Visual Studio Code, accessed on July 19, 2025, [https://code.visualstudio.com/docs/cpp/config-mingw](https://code.visualstudio.com/docs/cpp/config-mingw)  
8. CMake projects in Visual Studio | Microsoft Learn, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/cpp/build/cmake-projects-in-visual-studio?view=msvc-170](https://learn.microsoft.com/en-us/cpp/build/cmake-projects-in-visual-studio?view=msvc-170)  
9. Install OpenCV on Windows \- C++ / Python \- LearnOpenCV, accessed on July 19, 2025, [https://learnopencv.com/install-opencv-on-windows/](https://learnopencv.com/install-opencv-on-windows/)  
10. Integrating OpenCV with Visual Studio C++ Projects on Windows \- Christian Mills, accessed on July 19, 2025, [https://christianjmills.com/posts/opencv-visual-studio-getting-started-tutorial/windows/](https://christianjmills.com/posts/opencv-visual-studio-getting-started-tutorial/windows/)  
11. Thread: OpenCV integration with Qt creator \- Qt Centre Forum, accessed on July 19, 2025, [https://www.qtcentre.org/threads/38861-OpenCV-integration-with-Qt-creator](https://www.qtcentre.org/threads/38861-OpenCV-integration-with-Qt-creator)  
12. Tutorial: Install and use packages with CMake in Visual Studio Code \- Learn Microsoft, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/vcpkg/get\_started/get-started-vscode](https://learn.microsoft.com/en-us/vcpkg/get_started/get-started-vscode)  
13. C++ design patterns and architecture for building computational/numerical software for non computer scientist/classical programmer. : r/cpp \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cpp/comments/uu3vn4/c\_design\_patterns\_and\_architecture\_for\_building/](https://www.reddit.com/r/cpp/comments/uu3vn4/c_design_patterns_and_architecture_for_building/)  
14. Layers – MC++ BLOG \- Modernes C++, accessed on July 19, 2025, [https://www.modernescpp.com/index.php/layers/](https://www.modernescpp.com/index.php/layers/)  
15. Architecture Patterns ( MVC, MVP, MVVM) | by Bhushan Rane \- Medium, accessed on July 19, 2025, [https://medium.com/@bhushanrane1992/architecture-patterns-mvc-mvp-mvvm-b0441be6643a](https://medium.com/@bhushanrane1992/architecture-patterns-mvc-mvp-mvvm-b0441be6643a)  
16. Difference Between MVC, MVP and MVVM Architecture Pattern in Android \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/android/difference-between-mvc-mvp-and-mvvm-architecture-pattern-in-android/](https://www.geeksforgeeks.org/android/difference-between-mvc-mvp-and-mvvm-architecture-pattern-in-android/)  
17. MVP (Model View Presenter) Architecture Pattern in Android with Example \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/android/mvp-model-view-presenter-architecture-pattern-in-android-with-example/](https://www.geeksforgeeks.org/android/mvp-model-view-presenter-architecture-pattern-in-android-with-example/)  
18. MVVM (Model View ViewModel) Architecture Pattern in Android \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/android/mvvm-model-view-viewmodel-architecture-pattern-in-android/](https://www.geeksforgeeks.org/android/mvvm-model-view-viewmodel-architecture-pattern-in-android/)  
19. MVP Design \- Developer Documentation, accessed on July 19, 2025, [https://developer.mantidproject.org/MVPDesign.html](https://developer.mantidproject.org/MVPDesign.html)  
20. Salted Password Hashing \- Doing it Right \- CodeProject, accessed on July 19, 2025, [https://www.codeproject.com/Articles/704865/Salted-Password-Hashing-Doing-it-Right](https://www.codeproject.com/Articles/704865/Salted-Password-Hashing-Doing-it-Right)  
21. Adding Salt to Hashing: A Better Way to Store Passwords \- Auth0, accessed on July 19, 2025, [https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/](https://auth0.com/blog/adding-salt-to-hashing-a-better-way-to-store-passwords/)  
22. argon2 vs bcrypt vs scrypt vs pbkdf2 : r/cryptography \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cryptography/comments/11tqci2/argon2\_vs\_bcrypt\_vs\_scrypt\_vs\_pbkdf2/](https://www.reddit.com/r/cryptography/comments/11tqci2/argon2_vs_bcrypt_vs_scrypt_vs_pbkdf2/)  
23. Password Hashing \- Botan, accessed on July 19, 2025, [https://botan.randombit.net/handbook/api\_ref/passhash.html](https://botan.randombit.net/handbook/api_ref/passhash.html)  
24. PBKDF2 \- Practical Cryptography for Developers, accessed on July 19, 2025, [https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2](https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2)  
25. Encrypt and decrypt text file using C++ \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/cpp/encrypt-and-decrypt-text-file-using-cpp/](https://www.geeksforgeeks.org/cpp/encrypt-and-decrypt-text-file-using-cpp/)  
26. Tutorial: AES Encryption and Decryption with OpenSSL \- EclipseSource, accessed on July 19, 2025, [https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/](https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/)  
27. Encryption Key Management—What You Need to Know \- CrashPlan, accessed on July 19, 2025, [https://www.crashplan.com/blog/encryption-key-management-what-you-need-to-know/](https://www.crashplan.com/blog/encryption-key-management-what-you-need-to-know/)  
28. Encrypt/Decrypt Files using AES Cryptography (Visual Studio) Part 1 \- YouTube, accessed on July 19, 2025, [https://www.youtube.com/watch?v=73HPf4XfePM](https://www.youtube.com/watch?v=73HPf4XfePM)  
29. AES Encrypt / Decrypt \- Examples | Practical Cryptography for Developers, accessed on July 19, 2025, [https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples](https://cryptobook.nakov.com/symmetric-key-ciphers/aes-encrypt-decrypt-examples)  
30. C++ AES 256-bit CBC using PBKDF2 Generated Secret Key \- Chilkat Examples, accessed on July 19, 2025, [https://www.example-code.com/cpp/aes\_cbc\_256\_pbkdf2\_password.asp](https://www.example-code.com/cpp/aes_cbc_256_pbkdf2_password.asp)  
31. simple AES encryption/decryption example with PBKDF2 key derivation in Go, Javascript, and Python \- GitHub Gist, accessed on July 19, 2025, [https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47](https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47)  
32. Using crypto++ to encrypt and decrypt strings \- CPlusPlus.com, accessed on July 19, 2025, [https://cplusplus.com/forum/beginner/60604/](https://cplusplus.com/forum/beginner/60604/)  
33. PBKDF2 \- Wikipedia, accessed on July 19, 2025, [https://en.wikipedia.org/wiki/PBKDF2](https://en.wikipedia.org/wiki/PBKDF2)  
34. Brief Introduction to Crypto++ \- petanode, accessed on July 19, 2025, [https://petanode.com/posts/brief-introduction-to-cryptopp/](https://petanode.com/posts/brief-introduction-to-cryptopp/)  
35. AES Encryption Using Crypto++ .lib in Visual Studio C++ \- Red Team Notes, accessed on July 19, 2025, [https://www.ired.team/miscellaneous-reversing-forensics/aes-encryption-example-using-cryptopp-.lib-in-visual-studio-c++](https://www.ired.team/miscellaneous-reversing-forensics/aes-encryption-example-using-cryptopp-.lib-in-visual-studio-c++)  
36. Encrypt with Crypto++ and Decrypt with Python.CRYPTO \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/41700910/encrypt-with-crypto-and-decrypt-with-python-crypto](https://stackoverflow.com/questions/41700910/encrypt-with-crypto-and-decrypt-with-python-crypto)  
37. RandomNumberGenerator \- Crypto++ Wiki, accessed on July 19, 2025, [https://www.cryptopp.com/wiki/RandomNumberGenerator](https://www.cryptopp.com/wiki/RandomNumberGenerator)  
38. c++ \- How to read and write an AES key to and from a file? \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/45186444/how-to-read-and-write-an-aes-key-to-and-from-a-file](https://stackoverflow.com/questions/45186444/how-to-read-and-write-an-aes-key-to-and-from-a-file)  
39. 8 Cryptographic Key Management Best Practices \- YouTube, accessed on July 19, 2025, [https://m.youtube.com/watch?v=5CBkDknC-hI](https://m.youtube.com/watch?v=5CBkDknC-hI)  
40. Best security practices when writing C/C++ code : r/cpp \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cpp/comments/mvg2mi/best\_security\_practices\_when\_writing\_cc\_code/](https://www.reddit.com/r/cpp/comments/mvg2mi/best_security_practices_when_writing_cc_code/)  
41. Secure Coding in C++: Avoid Buffer Overflows and Memory Leaks \- Andela, accessed on July 19, 2025, [https://www.andela.com/blog-posts/secure-coding-in-c-avoid-buffer-overflows-and-memory-leaks](https://www.andela.com/blog-posts/secure-coding-in-c-avoid-buffer-overflows-and-memory-leaks)  
42. OpenCv and Visual C++ Face detection \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/45179908/opencv-and-visual-c-face-detection](https://stackoverflow.com/questions/45179908/opencv-and-visual-c-face-detection)  
43. C++ code to read images from webcam using CV 4.1.1 · GitHub, accessed on July 19, 2025, [https://gist.github.com/priteshgohil/edce691cf557e7e3bb708ff100a18da3](https://gist.github.com/priteshgohil/edce691cf557e7e3bb708ff100a18da3)  
44. IP Camera access using OpenCV \- c++ \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/21324785/ip-camera-access-using-opencv](https://stackoverflow.com/questions/21324785/ip-camera-access-using-opencv)  
45. What is the best algorithm for face detection using opencv and raspberry camera module, accessed on July 19, 2025, [https://stackoverflow.com/questions/31161341/what-is-the-best-algorithm-for-face-detection-using-opencv-and-raspberry-camera](https://stackoverflow.com/questions/31161341/what-is-the-best-algorithm-for-face-detection-using-opencv-and-raspberry-camera)  
46. OPENCV & C++ TUTORIALS \- 151 | Cascade Classifier \- YouTube, accessed on July 19, 2025, [https://www.youtube.com/watch?v=Yq9JKSLke3Q](https://www.youtube.com/watch?v=Yq9JKSLke3Q)  
47. Guide to Haar Cascade Algorithm with Object Detection Example \- Analytics Vidhya, accessed on July 19, 2025, [https://www.analyticsvidhya.com/blog/2022/04/object-detection-using-haar-cascade-opencv/](https://www.analyticsvidhya.com/blog/2022/04/object-detection-using-haar-cascade-opencv/)  
48. Face Detection using Haar Cascades \- OpenCV Documentation, accessed on July 19, 2025, [https://docs.opencv.org/4.x/d2/d99/tutorial\_js\_face\_detection.html](https://docs.opencv.org/4.x/d2/d99/tutorial_js_face_detection.html)  
49. OpenCV Face detection with Haar cascades \- PyImageSearch, accessed on July 19, 2025, [https://pyimagesearch.com/2021/04/05/opencv-face-detection-with-haar-cascades/](https://pyimagesearch.com/2021/04/05/opencv-face-detection-with-haar-cascades/)  
50. Cascade Classifier \- OpenCV Documentation, accessed on July 19, 2025, [https://docs.opencv.org/4.x/db/d28/tutorial\_cascade\_classifier.html](https://docs.opencv.org/4.x/db/d28/tutorial_cascade_classifier.html)  
51. Real time Face Detection using OpenCV-C++ \- GitHub, accessed on July 19, 2025, [https://github.com/AnirudhTripathi/Real-time-Face-Detection](https://github.com/AnirudhTripathi/Real-time-Face-Detection)  
52. OpenCV C++ Program for Face Detection \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/cpp/opencv-c-program-face-detection/](https://www.geeksforgeeks.org/cpp/opencv-c-program-face-detection/)  
53. OPENCV & C++ TUTORIALS \- 164 | YuNet Face Detector \- YouTube, accessed on July 19, 2025, [https://www.youtube.com/watch?v=8347U7s7wEQ](https://www.youtube.com/watch?v=8347U7s7wEQ)  
54. Face Recognition with OpenCV, accessed on July 19, 2025, [https://docs.opencv.org/3.4/da/d60/tutorial\_face\_main.html](https://docs.opencv.org/3.4/da/d60/tutorial_face_main.html)  
55. OpenCV \- Face Recognition using LBPH Classifier in C++ ..., accessed on July 19, 2025, [https://insightfultscript.com/collections/programming/cpp/opencv/opencv-creating-own-dataset-cpp/](https://insightfultscript.com/collections/programming/cpp/opencv/opencv-creating-own-dataset-cpp/)  
56. Face Recognition with OpenCV \- objc.io, accessed on July 19, 2025, [https://www.objc.io/issues/21-camera-and-photos/face-recognition-with-opencv](https://www.objc.io/issues/21-camera-and-photos/face-recognition-with-opencv)  
57. DNN-based Face Detection And Recognition \- OpenCV Documentation, accessed on July 19, 2025, [https://docs.opencv.org/4.x/d0/dd4/tutorial\_dnn\_face.html](https://docs.opencv.org/4.x/d0/dd4/tutorial_dnn_face.html)  
58. Face Recognition Benchmarks | 3DiVi Inc., accessed on July 19, 2025, [https://3divi.ai/resources/benchmarks](https://3divi.ai/resources/benchmarks)  
59. Face Recognition Benchmarks \- Paravision, accessed on July 19, 2025, [https://www.paravision.ai/benchmarks/](https://www.paravision.ai/benchmarks/)  
60. show webcam stream from OpenCV with Qt \- c++ \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/37462330/show-webcam-stream-from-opencv-with-qt](https://stackoverflow.com/questions/37462330/show-webcam-stream-from-opencv-with-qt)  
61. What are your GO-TO C++ GUI libraries in 2023 \! (Obscure ones too) : r/cpp \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cpp/comments/1871fzm/what\_are\_your\_goto\_c\_gui\_libraries\_in\_2023/](https://www.reddit.com/r/cpp/comments/1871fzm/what_are_your_goto_c_gui_libraries_in_2023/)  
62. Thread: Best Practice \- Qt Designer or Code?, accessed on July 19, 2025, [https://www.qtcentre.org/threads/48084-Best-Practice-Qt-Designer-or-Code](https://www.qtcentre.org/threads/48084-Best-Practice-Qt-Designer-or-Code)  
63. Best Practices for QML and Qt Quick, accessed on July 19, 2025, [https://doc.qt.io/qt-6/qtquick-bestpractices.html](https://doc.qt.io/qt-6/qtquick-bestpractices.html)  
64. Camera Example | Qt Multimedia | Qt 6.9.1, accessed on July 19, 2025, [https://doc.qt.io/qt-6/qtmultimedia-camera-example.html](https://doc.qt.io/qt-6/qtmultimedia-camera-example.html)  
65. How to Set a QLabel color using QColor \- Amin, accessed on July 19, 2025, [https://amin-ahmadi.com/2016/01/04/set-qlabel-qfont-qcolor-in-qt/](https://amin-ahmadi.com/2016/01/04/set-qlabel-qfont-qcolor-in-qt/)  
66. Thread: efficient way to display opencv image into Qt \- Qt Centre Forum, accessed on July 19, 2025, [https://www.qtcentre.org/threads/56482-efficient-way-to-display-opencv-image-into-Qt](https://www.qtcentre.org/threads/56482-efficient-way-to-display-opencv-image-into-Qt)  
67. SFML Graphics Library | Quick Tutorial \- GeeksforGeeks, accessed on July 19, 2025, [https://www.geeksforgeeks.org/computer-graphics/sfml-graphics-library-quick-tutorial/](https://www.geeksforgeeks.org/computer-graphics/sfml-graphics-library-quick-tutorial/)  
68. OpenCV mat to SFML image \- c++ \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/28272950/opencv-mat-to-sfml-image](https://stackoverflow.com/questions/28272950/opencv-mat-to-sfml-image)  
69. Top 10 secure C++ coding practices \- incredibuild, accessed on July 19, 2025, [https://www.incredibuild.com/blog/top-10-secure-c-coding-practices](https://www.incredibuild.com/blog/top-10-secure-c-coding-practices)  
70. 8 Types of Code Injection and 8 Ways to Prevent Them \- Oligo Security, accessed on July 19, 2025, [https://www.oligo.security/academy/8-types-of-code-injection-and-8-ways-to-prevent-them](https://www.oligo.security/academy/8-types-of-code-injection-and-8-ways-to-prevent-them)  
71. What are the best practices systems use to prevent buffer overflows? \- Quora, accessed on July 19, 2025, [https://www.quora.com/What-are-the-best-practices-systems-use-to-prevent-buffer-overflows](https://www.quora.com/What-are-the-best-practices-systems-use-to-prevent-buffer-overflows)  
72. Preventing SQL injection with C++ : r/cpp\_questions \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cpp\_questions/comments/10dm42p/preventing\_sql\_injection\_with\_c/](https://www.reddit.com/r/cpp_questions/comments/10dm42p/preventing_sql_injection_with_c/)  
73. Secure C++ coding practices \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/4780410/secure-c-coding-practices](https://stackoverflow.com/questions/4780410/secure-c-coding-practices)  
74. Secure Coding Practices Checklist \- OWASP Foundation, accessed on July 19, 2025, [https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/stable-en/02-checklist/05-checklist)  
75. Write unit tests for C/C++ \- Visual Studio (Windows) | Microsoft Learn, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/visualstudio/test/writing-unit-tests-for-c-cpp?view=vs-2022](https://learn.microsoft.com/en-us/visualstudio/test/writing-unit-tests-for-c-cpp?view=vs-2022)  
76. What is your approach to testing? : r/cpp \- Reddit, accessed on July 19, 2025, [https://www.reddit.com/r/cpp/comments/qxp00b/what\_is\_your\_approach\_to\_testing/](https://www.reddit.com/r/cpp/comments/qxp00b/what_is_your_approach_to_testing/)  
77. 15 Best Practices of Application Security Testing with Data Encryption \- Terralogic, accessed on July 19, 2025, [https://terralogic.com/application-testing-with-data-encryption/](https://terralogic.com/application-testing-with-data-encryption/)  
78. Unit Testing Tool for C and C++ \- Optimize Testing \- Parasoft, accessed on July 19, 2025, [https://www.parasoft.com/products/parasoft-c-ctest/unit-testing/](https://www.parasoft.com/products/parasoft-c-ctest/unit-testing/)  
79. Writing Correct C++ GUI Code: Bug-Free JUCE UI \- Jan Wilczek \- ADC 2024 \- YouTube, accessed on July 19, 2025, [https://www.youtube.com/watch?v=Ur\_sTOe-1LI](https://www.youtube.com/watch?v=Ur_sTOe-1LI)  
80. Qt Test Overview \- Qt Documentation, accessed on July 19, 2025, [https://doc.qt.io/qt-6/qtest-overview.html](https://doc.qt.io/qt-6/qtest-overview.html)  
81. How to create an MSI installer for your C++ application in Visual Studio, accessed on July 19, 2025, [https://www.advancedinstaller.com/create-msi-installer-for-cpp-application-visual-studio.html](https://www.advancedinstaller.com/create-msi-installer-for-cpp-application-visual-studio.html)  
82. Walkthrough: Deploying Your Program (C++) \- Learn Microsoft, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/cpp/ide/walkthrough-deploying-your-program-cpp?view=msvc-170](https://learn.microsoft.com/en-us/cpp/ide/walkthrough-deploying-your-program-cpp?view=msvc-170)  
83. How to distribute an application with libraries? \- c++ \- Stack Overflow, accessed on July 19, 2025, [https://stackoverflow.com/questions/34720922/how-to-distribute-an-application-with-libraries](https://stackoverflow.com/questions/34720922/how-to-distribute-an-application-with-libraries)  
84. Best practice of c/C++ dependency management on build servers?, accessed on July 19, 2025, [https://softwareengineering.stackexchange.com/questions/381562/best-practice-of-c-c-dependency-management-on-build-servers](https://softwareengineering.stackexchange.com/questions/381562/best-practice-of-c-c-dependency-management-on-build-servers)  
85. Signing a Windows app | Electron Forge, accessed on July 19, 2025, [https://www.electronforge.io/guides/code-signing/code-signing-windows](https://www.electronforge.io/guides/code-signing/code-signing-windows)  
86. Sign application and deployment manifests \- Visual Studio (Windows) | Microsoft Learn, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/visualstudio/ide/how-to-sign-application-and-deployment-manifests?view=vs-2022](https://learn.microsoft.com/en-us/visualstudio/ide/how-to-sign-application-and-deployment-manifests?view=vs-2022)  
87. SignTool \- Win32 apps \- Learn Microsoft, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)  
88. SignTool.exe (Sign Tool) \- .NET Framework \- Learn Microsoft, accessed on July 19, 2025, [https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe](https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe)