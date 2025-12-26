package io.dice52;

import java.nio.charset.StandardCharsets;

/**
 * Constants and protocol-specified info strings for the Dice52 protocol.
 */
public final class Constants {

    private Constants() {
        // Utility class
    }

    /** Protocol version */
    public static final int VERSION = 1;

    /** Key length in bytes */
    public static final int KEY_LEN = 32;

    /** Section 14: Default maximum messages per epoch */
    public static final int DEFAULT_MAX_MESSAGES_PER_EPOCH = 33;

    // Protocol-specified info strings (Section 8, 9, 10)
    public static final byte[] RK_INFO = "Dice52-RK".getBytes(StandardCharsets.UTF_8);
    public static final byte[] KO_INFO = "Dice52-Ko".getBytes(StandardCharsets.UTF_8);
    public static final byte[] CKS_INFO = "Dice52-CKs".getBytes(StandardCharsets.UTF_8);
    public static final byte[] CKR_INFO = "Dice52-CKr".getBytes(StandardCharsets.UTF_8);
    public static final byte[] MK_INFO = "Dice52-MK".getBytes(StandardCharsets.UTF_8);

    // Ratchet info (Section 13)
    public static final byte[] RK_RATCHET_INFO = "Dice52-RK-Ratchet".getBytes(StandardCharsets.UTF_8);

    // Ko enhancement info strings (Section 7.1)
    public static final byte[] KO_COMMIT_PREFIX = "Dice52-Ko-Commit".getBytes(StandardCharsets.UTF_8);
    public static final byte[] KO_COMMIT_KEY_INFO = "Dice52-Ko-CommitKey".getBytes(StandardCharsets.UTF_8);
    public static final byte[] KO_ENHANCED_INFO = "Dice52-Ko-Enhanced".getBytes(StandardCharsets.UTF_8);

    // Signature context (Section 4)
    public static final byte[] SIG_CONTEXT = "Dice52-PQ-Signature".getBytes(StandardCharsets.UTF_8);
}
