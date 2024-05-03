# Damn Vulnerable Golang Application

This repository contains a deliberately vulnerable golang (go) application designed to demonstrate unsafe programming practices and common security vulnerabilities. The purpose of this application is to serve as an educational resource for developers to learn about secure coding practices and to test static analysis tools.

## Disclaimer

:warning: **WARNING: This application contains intentionally vulnerable code and should never be run in a production environment or used for any real-world purposes. Running this code can potentially harm your system or expose it to security risks.** :warning:

The vulnerabilities present in this code are for educational and testing purposes only. They are designed to highlight the importance of secure coding practices and to provide a platform for testing static analysis tools.

## Purpose

The main objectives of this repository are:

1. To demonstrate unsafe programming practices and common security vulnerabilities in go applications.
2. To serve as a resource for developers to learn about secure coding practices and how to avoid common pitfalls.
3. To provide a test suite for evaluating the effectiveness of static analysis tools in detecting vulnerabilities.

## Vulnerabilities

The code in this repository contains various intentional vulnerabilities, including but not limited to:

- SQL Injection
- Command Injection
- Path Traversal
- Weak Cryptography
- Hardcoded Credentials
- Integer Overflow
- Denial-of-Service (DoS)

Each vulnerability is accompanied by comments explaining the issue, the associated [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/), and best practices to mitigate the vulnerability.

## Usage

To compile the vulnerable application, use the following command:

```shell
go build main.go
```

However, it is strongly recommended **NOT** to run the compiled binary, as it may cause harm to your system or expose it to security risks.

Instead, you can use this repository to:

- Study the vulnerable code and understand the security issues present.
- Test static analysis tools to evaluate their effectiveness in detecting the vulnerabilities.
- Learn about secure coding practices and how to prevent common vulnerabilities in go applications.

## Contributing

As this repository is meant for educational purposes and contains intentionally vulnerable code, contributions are not accepted. However, if you have suggestions for additional vulnerabilities or improvements to the existing code, please open an issue to discuss them.

## License

This repository is licensed under the [Apache License 2.0](LICENSE).

## Disclaimer

The code in this repository is provided for educational and testing purposes only. The authors and contributors are not responsible for any damages or losses caused by the use or misuse of this code. Use it at your own risk.