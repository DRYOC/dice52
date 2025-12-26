# Dice52-PQ Java Implementation

A Java implementation of the Dice52-PQ post-quantum ratcheting protocol.

## Requirements

- Java 17+
- Maven 3.8+

## Dependencies

- Bouncy Castle (for ML-KEM/Kyber, ML-DSA/Dilithium, ChaCha20-Poly1305, HKDF)
- Gson (for JSON serialization)
- JUnit 5 (for testing)

## Building

```bash
# Build the project
mvn package -DskipTests

# Or using the Makefile
make build
```

## Running the Demo

```bash
mvn exec:java

# Or using the Makefile
make demo
```

## Testing

```bash
mvn test

# Or using the Makefile
make test
```

## Usage

```java
import io.dice52.*;

// Generate key pairs
byte[][] kemKeysA = Handshake.generateKemKeypair();
byte[][] kemKeysB = Handshake.generateKemKeypair();
byte[][] idKeysA = Handshake.generateSigningKeypair();
byte[][] idKeysB = Handshake.generateSigningKeypair();

// Key exchange
byte[][] encapResult = Handshake.initiatorEncapsulate(kemKeysB[0]);
byte[] ssAlice = encapResult[0];
byte[] ct = encapResult[1];
byte[] ssBob = Handshake.responderDecapsulate(kemKeysB[1], ct);

// Derive session keys
byte[][] keysAlice = Kdf.deriveInitialKeys(ssAlice);
byte[][] chainKeysAlice = Kdf.initChainKeys(keysAlice[0], keysAlice[1]);

byte[][] keysBob = Kdf.deriveInitialKeys(ssBob);
byte[][] chainKeysBob = Kdf.initChainKeys(keysBob[0], keysBob[1]);

// Create sessions
Session alice = new Session(
    1,                    // sessionId
    keysAlice[0],         // rk
    keysAlice[1],         // ko
    chainKeysAlice[0],    // cks
    chainKeysAlice[1],    // ckr
    kemKeysA[0],          // kemPub
    kemKeysA[1],          // kemPriv
    idKeysA[0],           // idPub
    idKeysA[1],           // idPriv
    idKeysB[0],           // peerId
    true                  // isInitiator
);

Session bob = new Session(
    1,
    keysBob[0],
    keysBob[1],
    chainKeysBob[1],      // Swapped!
    chainKeysBob[0],      // Swapped!
    kemKeysB[0],
    kemKeysB[1],
    idKeysB[0],
    idKeysB[1],
    idKeysA[0],
    false
);

// Send messages
Types.Message msg = alice.send("Hello, quantum-safe world!".getBytes());
byte[] plaintext = bob.receive(msg);
System.out.println(new String(plaintext));  // "Hello, quantum-safe world!"
```

## Warning

This is an experimental protocol implementation. Do NOT use in production systems.

