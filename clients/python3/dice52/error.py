"""Dice52 error types."""


class Dice52Error(Exception):
    """Base exception for Dice52 protocol errors."""
    pass


class InvalidHandshakeSignature(Dice52Error):
    """Invalid signature in handshake message."""
    pass


class InvalidRatchetSignature(Dice52Error):
    """Invalid signature in ratchet message."""
    pass


class KemError(Dice52Error):
    """KEM operation error."""
    pass


class DecryptionFailed(Dice52Error):
    """AEAD decryption failed."""
    pass


class EpochExhausted(Dice52Error):
    """Epoch message limit reached."""
    pass


class EpochMismatch(Dice52Error):
    """Received message epoch doesn't match session epoch."""
    pass


class ReplayDetected(Dice52Error):
    """Message replay detected."""
    pass


class KoEnhancementError(Dice52Error):
    """Ko enhancement protocol error."""
    pass


class KoCommitMismatch(Dice52Error):
    """Ko commit verification failed."""
    pass


class ConfigError(Dice52Error):
    """Configuration error."""
    pass

