# A38 MotorIST

## Team

| Number | Name           | User                                  | E-mail                              |
|--------|----------------|---------------------------------------|-------------------------------------|
| 112467 | Elie Bruno     | <https://github.com/FlavienVa>        | <elie.bruno@tecnico.ulisboa.pt>     |
| 112848 | Flavien Valea  | <https://github.com/eliemada>         | <flavien.valea@tecnico.ulisboa.pt> |
| 112763 | Tanguy Vésy    | <https://github.com/TonyVesy>         | <tanguy.vesy@tecnico.ulisboa.pt>   |

---

## 1. Introduction

The **MotorIST** project involves selling electric cars equipped with modern management systems. These systems allow users to configure their cars remotely, such as locking/unlocking, adjusting air conditioning, and monitoring battery levels. The vehicles can also receive secure firmware updates from the manufacturer to ensure performance, security, and compliance. 

The project focuses on ensuring secure communication of sensitive data within the car ecosystem while complying with **GDPR (General Data Protection Regulation)** standards. It meets crucial security requirements, including:

- **Confidentiality:** Only authorized users can access car configurations.
- **Integrity:** Firmware updates are validated, ensuring no tampering occurs.
- **Authentication:** The integrity and legitimacy of configurations or updates must be verifiable by all stakeholders.

### Infrastructure Diagram

Below is the system architecture for MotorIST:

![System Diagram](img/diagram.jpg)

---

## 2. Project Development

### 2.1. Secure Document Format

#### 2.1.1. Design

The secure document format integrates cryptographic measures to protect all communication in our project. It uses the following features:

- **Encryption:** AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode) ensures confidentiality and authenticity of shared configurations.
- **Digital Signatures:** ECDSA (Elliptic Curve Digital Signature Algorithm) signs messages to ensure integrity and non-repudiation.
- **Freshness:** A timestamp and a nonce prevent replay attacks.

##### **Why We Use Both**
Combining a **nonce** with a **timestamp** mitigates the limitations of using each individually and strengthens the overall security:

1. **Preventing Reuse of Messages**:
   - The **nonce** ensures every message is unique, even if two messages are sent with the same content and timestamp.

2. **Efficient State Management**:
   - By using both, the recipient can combine the timestamp and nonce for validation:
     - Only nonces from recent timestamps need to be cached.
     - Old nonces can be discarded automatically based on the timestamp, reducing memory usage.

3. **Replay Protection Across Time**:
   - The **timestamp** ensures freshness, so even if an attacker replays a message with a valid nonce, it will be rejected if the timestamp falls outside the allowed time window.

4. **Resilience Against Clock Drift**:
   - The nonce provides additional uniqueness, making the system more resilient to minor clock drift between sender and receiver.


#### 2.1.2. Implementation

The system uses **Java**, leveraging the **BouncyCastle** cryptographic library for robust encryption, signing, and key management. Key challenges included ensuring compatibility across devices and preventing replay attacks, tackled via timestamp and nonce validations.

---

### 2.2. Infrastructure

#### 2.2.1. Network and Machine Setup

- **User**: Communicate with the car.
- **Manufacturer**: Communicate with the webserver and the car. 
- **Web Server**: Hosts the car configuration portal. It uses SSL/TLS for encrypted communication.
- **Car Interface**: Communicates over a secure channel with user devices and manufacturers.
- **Mechanic**: Communicates with the user to get his approuval (privateKey) and can then access the car configuration.

#### 2.2.2. Server Communication Security

- **Encryption**: TLSv1.3 is used for all communications.
- **Keys**: AES session keys are dynamically generated and shared via RSA encryption. Public/private key pairs are distributed securely to stakeholders during initial setup.
- **Auditing**: An audit of configuration updates ensures the system addresses [SRA3: authenticity].

---

### 2.3. Security Challenge

#### 2.3.1. Challenge Overview

The introduction of multiple users added complexity, requiring:
- Segregation of configurations between users.
- Enhanced auditing capabilities to track actions by individual users.

#### 2.3.2. Attacker Model

- **Trusted Entities**: Manufacturer and Car.
- **Untrusted Entities**: External attackers attempting to intercept or manipulate data.

#### 2.3.3. Solution Design and Implementation

The system uses the following enhancements:
- **Access Controls**: Unique keys identify users, ensuring that each configuration update is authenticated ([SR2: Integrity 1]).
- **Audit Logging**: Logs store configuration action metadata, meeting [SRA3: authenticity].
- **Secure Firmware Distribution**: Firmware updates are signed and verified per [SR4: Authentication].

---

## 3. Conclusion

The project has successfully implemented secure mechanisms to meet requirements, including:
- [SR1]: Confidentiality of car configurations.
- [SR2]: Integrity of owner-sent configurations.
- [SR3]: Integrity of firmware updates sent by the manufacturer.

Future enhancements could involve:
- Extending configuration capabilities to mobile platforms.
- Real-time alerts for unauthorized access attempts.

This project highlights the critical importance of secure communication in modern automotive systems.

---

## 4. Bibliography

- NIST. "Guidelines for AES". NIST Publications, 2001.
- Diffie, W., & Hellman, M. "New Directions in Cryptography". IEEE, 1976.
- <https://bouncycastle.org/> - BouncyCastle Library Documentation.
- <https://www.rfc-editor.org/info/rfc5280> - RFC 5280: Public Key Infrastructure Standards.
