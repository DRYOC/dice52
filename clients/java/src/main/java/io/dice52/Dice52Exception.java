package io.dice52;

/**
 * Base exception for Dice52 protocol errors.
 */
public class Dice52Exception extends Exception {

    public Dice52Exception(String message) {
        super(message);
    }

    public Dice52Exception(String message, Throwable cause) {
        super(message, cause);
    }

    /** Invalid signature in handshake message. */
    public static class InvalidHandshakeSignature extends Dice52Exception {
        public InvalidHandshakeSignature(String message) {
            super(message);
        }
    }

    /** Invalid signature in ratchet message. */
    public static class InvalidRatchetSignature extends Dice52Exception {
        public InvalidRatchetSignature(String message) {
            super(message);
        }
    }

    /** KEM operation error. */
    public static class KemError extends Dice52Exception {
        public KemError(String message) {
            super(message);
        }

        public KemError(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** AEAD decryption failed. */
    public static class DecryptionFailed extends Dice52Exception {
        public DecryptionFailed(String message) {
            super(message);
        }

        public DecryptionFailed(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** Epoch message limit reached. */
    public static class EpochExhausted extends Dice52Exception {
        public EpochExhausted(String message) {
            super(message);
        }
    }

    /** Received message epoch doesn't match session epoch. */
    public static class EpochMismatch extends Dice52Exception {
        public EpochMismatch(String message) {
            super(message);
        }
    }

    /** Message replay detected. */
    public static class ReplayDetected extends Dice52Exception {
        public ReplayDetected(String message) {
            super(message);
        }
    }

    /** Ko enhancement protocol error. */
    public static class KoEnhancementError extends Dice52Exception {
        public KoEnhancementError(String message) {
            super(message);
        }
    }

    /** Ko commit verification failed. */
    public static class KoCommitMismatch extends Dice52Exception {
        public KoCommitMismatch(String message) {
            super(message);
        }
    }

    /** Configuration error. */
    public static class ConfigError extends Dice52Exception {
        public ConfigError(String message) {
            super(message);
        }
    }
}
