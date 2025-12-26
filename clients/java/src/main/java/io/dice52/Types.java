package io.dice52;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.nio.charset.StandardCharsets;

/**
 * Types for the Dice52 protocol.
 */
public class Types {

    private static final Gson gson = new Gson();

    /**
     * Paranoid mode configuration (Section 7.2).
     */
    public static class ParanoidConfig {
        public boolean enabled;
        public int koReenhanceInterval; // 0 = never re-enhance after initial
        public int maxMessagesPerEpoch;

        public ParanoidConfig() {
            this.enabled = false;
            this.koReenhanceInterval = 0;
            this.maxMessagesPerEpoch = Constants.DEFAULT_MAX_MESSAGES_PER_EPOCH;
        }

        public static ParanoidConfig defaultConfig() {
            ParanoidConfig config = new ParanoidConfig();
            config.enabled = true;
            config.koReenhanceInterval = 10; // Re-enhance Ko every 10 epochs
            config.maxMessagesPerEpoch = 16; // Reduced from 33 to 16
            return config;
        }

        public void validate() throws Dice52Exception.ConfigError {
            if (maxMessagesPerEpoch < 1) {
                throw new Dice52Exception.ConfigError("maxMessagesPerEpoch must be >= 1");
            }
            if (maxMessagesPerEpoch > 33) {
                throw new Dice52Exception.ConfigError("maxMessagesPerEpoch must be <= 33");
            }
        }
    }

    /**
     * Handshake message for initial key exchange.
     */
    public static class HandshakeMessage {
        public byte[] kyberCt;
        public byte[] sig;

        public HandshakeMessage(byte[] kyberCt, byte[] sig) {
            this.kyberCt = kyberCt;
            this.sig = sig;
        }
    }

    /**
     * Encrypted message with header and body.
     */
    public static class Message {
        public String header; // Base64-encoded header (JSON)
        public String body; // Base64-encoded ciphertext

        public Message(String header, String body) {
            this.header = header;
            this.body = body;
        }
    }

    /**
     * Ratchet message for PQ ratchet key exchange.
     */
    public static class RatchetMessage {
        public byte[] pubKey; // New KEM public key (for initiator)
        public byte[] sig; // Dilithium signature (for initiator)
        public byte[] ct; // KEM ciphertext (for responder)

        public RatchetMessage() {
        }

        public RatchetMessage(byte[] pubKey, byte[] sig, byte[] ct) {
            this.pubKey = pubKey;
            this.sig = sig;
            this.ct = ct;
        }
    }

    /**
     * Header includes all AD fields required by Section 11.1.
     */
    public static class Header {
        @SerializedName("v")
        public int version;
        @SerializedName("e")
        public long epoch;
        @SerializedName("n")
        public long msgNum;
        @SerializedName("d")
        public String direction;

        public Header() {
        }

        public Header(int version, long epoch, long msgNum, String direction) {
            this.version = version;
            this.epoch = epoch;
            this.msgNum = msgNum;
            this.direction = direction;
        }

        public byte[] toJson() {
            return gson.toJson(this).getBytes(StandardCharsets.UTF_8);
        }

        public static Header fromJson(byte[] data) {
            return gson.fromJson(new String(data, StandardCharsets.UTF_8), Header.class);
        }
    }

    /**
     * Ko enhancement commit message (Section 7.1.2).
     */
    public static class KoCommitMessage {
        public byte[] commitCt; // Encrypted SHA-256 commitment

        public KoCommitMessage(byte[] commitCt) {
            this.commitCt = commitCt;
        }
    }

    /**
     * Ko enhancement reveal message (Section 7.1.3).
     */
    public static class KoRevealMessage {
        public byte[] revealCt; // Encrypted local entropy

        public KoRevealMessage(byte[] revealCt) {
            this.revealCt = revealCt;
        }
    }

    /**
     * State for Ko enhancement protocol.
     */
    public static class KoEnhancementState {
        public byte[] tk; // Temporary key
        public byte[] localEntropy; // Our local entropy
        public byte[] localCommit; // Our commitment
        public byte[] peerCommit; // Peer's commitment
        public byte[] peerEntropy; // Peer's entropy

        public void zero() {
            if (tk != null)
                java.util.Arrays.fill(tk, (byte) 0);
            if (localEntropy != null)
                java.util.Arrays.fill(localEntropy, (byte) 0);
            if (localCommit != null)
                java.util.Arrays.fill(localCommit, (byte) 0);
            if (peerCommit != null)
                java.util.Arrays.fill(peerCommit, (byte) 0);
            if (peerEntropy != null)
                java.util.Arrays.fill(peerEntropy, (byte) 0);
        }
    }
}
