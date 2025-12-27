package io.dice52;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Key derivation functions using HKDF-SHA256.
 */
public class Kdf {

    private Kdf() {
        // Utility class
    }

    /**
     * Derive a key using HKDF-SHA256 (Section 3.2).
     */
    public static byte[] hkdfExpand(byte[] secret, byte[] info) {
        return hkdfExpand(secret, info, Constants.KEY_LEN);
    }

    public static byte[] hkdfExpand(byte[] secret, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(secret, null, info));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
    }

    /**
     * HKDF expand with salt.
     */
    public static byte[] hkdfExpandWithSalt(byte[] secret, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(secret, salt, info));
        byte[] out = new byte[length];
        hkdf.generateBytes(out, 0, length);
        return out;
    }

    /**
     * Derive hybrid shared secret from Kyber and X25519 shared secrets (Section
     * 3.1).
     * 
     * SS_hybrid = HKDF(SS_pq || SS_ecdh, "Dice52-Hybrid-SS")
     */
    public static byte[] deriveHybridSharedSecret(byte[] ssPq, byte[] ssEcdh) {
        byte[] combined = concat(ssPq, ssEcdh);
        return hkdfExpand(combined, Constants.HYBRID_SS_INFO);
    }

    /**
     * Derive RK and Ko from shared secret (Section 8).
     * 
     * @return array of [root_key, ko]
     */
    public static byte[][] deriveInitialKeys(byte[] ss) {
        byte[] rk = hkdfExpand(ss, Constants.RK_INFO);
        byte[] ko = hkdfExpand(rk, Constants.KO_INFO);
        return new byte[][] { rk, ko };
    }

    /**
     * Initialize CKs and CKr from RK and Ko (Section 9).
     * 
     * @return array of [chain_key_send, chain_key_receive]
     */
    public static byte[][] initChainKeys(byte[] rk, byte[] ko) {
        // CKs = HKDF(RK, "Dice52-CKs" || Ko)
        byte[] cksInfo = concat(Constants.CKS_INFO, ko);
        byte[] cks = hkdfExpand(rk, cksInfo);

        // CKr = HKDF(RK, "Dice52-CKr" || Ko)
        byte[] ckrInfo = concat(Constants.CKR_INFO, ko);
        byte[] ckr = hkdfExpand(rk, ckrInfo);

        return new byte[][] { cks, ckr };
    }

    /**
     * Perform a PQ ratchet step (Section 13.2).
     */
    public static byte[] ratchetRk(byte[] oldRk, byte[] ss, byte[] ko) {
        // RK = HKDF(RK || SS || Ko, "Dice52-RK-Ratchet")
        byte[] combined = concat(oldRk, ss, ko);
        return hkdfExpand(combined, Constants.RK_RATCHET_INFO);
    }

    /**
     * Derive the next chain key and message key (Section 10).
     * 
     * @return array of [next_chain_key, message_key]
     */
    public static byte[][] ckToMk(byte[] ck, byte[] ko, long n, byte dir, byte[] salt) {
        // Build info: MK_INFO || Ko || dir || n (8 bytes big-endian)
        ByteBuffer buf = ByteBuffer.allocate(Constants.MK_INFO.length + ko.length + 1 + 8);
        buf.put(Constants.MK_INFO);
        buf.put(ko);
        buf.put(dir);
        buf.putLong(n);
        byte[] info = buf.array();

        byte[] out = hkdfExpandWithSalt(ck, salt, info, 64);

        byte[] nextCk = Arrays.copyOfRange(out, 0, 32);
        byte[] mk = Arrays.copyOfRange(out, 32, 64);

        return new byte[][] { nextCk, mk };
    }

    // ============================================================================
    // Ko Enhancement Functions (Section 7.1)
    // ============================================================================

    /**
     * Derive the temporary key for Ko enhancement commit/reveal encryption.
     */
    public static byte[] deriveKoCommitKey(byte[] ss) {
        return hkdfExpand(ss, Constants.KO_COMMIT_KEY_INFO);
    }

    /**
     * Create a commitment to entropy (Section 7.1.2).
     */
    public static byte[] commitEntropy(int sessionId, byte[] entropy) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(Constants.KO_COMMIT_PREFIX);
            ByteBuffer sidBuf = ByteBuffer.allocate(4);
            sidBuf.putInt(sessionId);
            sha256.update(sidBuf.array());
            sha256.update(entropy);
            return sha256.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * Verify an entropy commitment (Section 7.1.3).
     */
    public static boolean verifyCommit(int sessionId, byte[] entropy, byte[] commit) {
        byte[] expected = commitEntropy(sessionId, entropy);
        return MessageDigest.isEqual(expected, commit);
    }

    /**
     * Derive enhanced Ko with contributed entropy from both parties (Section
     * 7.1.4).
     */
    public static byte[] deriveEnhancedKo(byte[] koBase, byte[] rInitiator, byte[] rResponder) {
        byte[] combined = concat(koBase, rInitiator, rResponder);
        return hkdfExpand(combined, Constants.KO_ENHANCED_INFO);
    }

    // ============================================================================
    // Helper methods
    // ============================================================================

    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }
}
