package io.dice52;

import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Cryptographic operations using ChaCha20-Poly1305.
 */
public class Crypto {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Crypto() {
        // Utility class
    }

    /**
     * Generate n random bytes using secure random.
     */
    public static byte[] randBytes(int n) {
        byte[] bytes = new byte[n];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Securely zero a byte array.
     */
    public static void zeroBytes(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Create a nonce including session ID, epoch and message number.
     * Nonce is 96 bits (12 bytes).
     */
    public static byte[] makeNonce(int sid, long epoch, long ctr) {
        ByteBuffer buffer = ByteBuffer.allocate(12);
        buffer.putInt(sid);
        buffer.putInt((int) epoch);
        buffer.putInt((int) ctr);
        return buffer.array();
    }

    /**
     * Encrypt plaintext using ChaCha20-Poly1305 (Section 11.2).
     */
    public static byte[] encrypt(byte[] mk, int sid, long epoch, long ctr, byte[] ad, byte[] pt) {
        try {
            byte[] nonce = makeNonce(sid, epoch, ctr);

            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            AEADParameters params = new AEADParameters(
                    new KeyParameter(mk),
                    128, // Tag size in bits
                    nonce,
                    ad);
            cipher.init(true, params);

            byte[] output = new byte[cipher.getOutputSize(pt.length)];
            int len = cipher.processBytes(pt, 0, pt.length, output, 0);
            cipher.doFinal(output, len);

            zeroBytes(nonce);
            return output;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt ciphertext using ChaCha20-Poly1305 (Section 12).
     */
    public static byte[] decrypt(byte[] mk, int sid, long epoch, long ctr, byte[] ad, byte[] ct)
            throws Dice52Exception.DecryptionFailed {
        try {
            if (ct.length < 16) {
                throw new Dice52Exception.DecryptionFailed("Ciphertext too short");
            }

            byte[] nonce = makeNonce(sid, epoch, ctr);

            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            AEADParameters params = new AEADParameters(
                    new KeyParameter(mk),
                    128, // Tag size in bits
                    nonce,
                    ad);
            cipher.init(false, params);

            byte[] output = new byte[cipher.getOutputSize(ct.length)];
            int len = cipher.processBytes(ct, 0, ct.length, output, 0);
            cipher.doFinal(output, len);

            zeroBytes(nonce);
            return output;
        } catch (Dice52Exception.DecryptionFailed e) {
            throw e;
        } catch (Exception e) {
            throw new Dice52Exception.DecryptionFailed("Decryption failed: " + e.getMessage(), e);
        }
    }
}
