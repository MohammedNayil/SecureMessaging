package com.project1.demo;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;

/**
 * MessageController (with timestamp + nonce + replay protection)
 *
 * Endpoints:
 *  - POST /api/keys/generate?userId=...
 *  - GET  /api/keys/public?userId=...
 *  - POST /api/message/send       (server generates AES key, encrypts, wraps, signs, stores package)
 *  - GET  /api/message/latest     (fetch stored package for sender->receiver)
 *  - POST /api/message/receive    (verify canonical payload, timestamp/window, nonce replay-check, unwrap AES key, AES-GCM decrypt)
 *
 * Security notes (demo):
 *  - Private keys and messages are stored in-memory for demonstration only.
 *  - The controller returns the raw AES key inside SendResponse (aesKey) for demo/troubleshooting only — remove in production.
 *  - Use TLS and proper authentication & secure key storage (keystore / HSM) for real deployments.
 */
@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api")
public class MessageController {

    // In-memory stores (demo only)
    private final Map<String, KeyPair> keyStore = new ConcurrentHashMap<>();
    private final Map<String, SendResponse> messageStore = new ConcurrentHashMap<>();
    private final Map<String, Long> usedNonces = new ConcurrentHashMap<>(); // nonce -> first-seen timestamp

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits recommended
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final long WINDOW_MILLIS = 5L * 60L * 1000L; // 5 minutes

// ---- Rate Limiting (Anti‑DoS) ----
private final Map<String, List<Long>> requestLog = new ConcurrentHashMap<>();

// Max 10 requests per 10 seconds per IP
private static final int MAX_REQUESTS = 10;
private static final long WINDOW_MS = 10_000;

    private void rateLimitCheck(HttpServletRequest request) {
    String ip = request.getRemoteAddr();
    long now = System.currentTimeMillis();

    requestLog.putIfAbsent(ip, Collections.synchronizedList(new ArrayList<>()));
    List<Long> timestamps = requestLog.get(ip);

    // Remove timestamps older than the window
    timestamps.removeIf(t -> (now - t) > WINDOW_MS);

    // If too many requests in the time window -> block
    if (timestamps.size() >= MAX_REQUESTS) {
        throw new ResponseStatusException(
            HttpStatus.TOO_MANY_REQUESTS,
            "Too many requests — temporarily blocked (DoS protection)"
        );
    }

    // Log new request time
    timestamps.add(now);
}

    /* ---------------------------
       Key management
       --------------------------- */

    @PostMapping("/keys/generate")
    public ResponseEntity<?> generateKeypair(@RequestParam String userId) {
        try {
            if (userId == null || userId.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("userId required");
            }
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, RANDOM);
            KeyPair kp = kpg.generateKeyPair();
            keyStore.put(userId, kp);

            String publicKeyB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            return ResponseEntity.ok(Map.of(
                    "userId", userId,
                    "publicKey", publicKeyB64,
                    "algorithm", "RSA",
                    "keySize", 2048
            ));
        } catch (NoSuchAlgorithmException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("RSA not supported: " + e.getMessage());
        }
    }

    @GetMapping("/keys/public")
    public ResponseEntity<?> getPublicKey(@RequestParam String userId) {
        KeyPair kp = keyStore.get(userId);
        if (kp == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No keypair for userId: " + userId);
        }
        String publicKeyB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
        return ResponseEntity.ok(Map.of(
                "userId", userId,
                "publicKey", publicKeyB64,
                "algorithm", "RSA",
                "keySize", 2048
        ));
    }

    /* ---------------------------
       Send: server-side create AES key, encrypt, wrap, sign, store
       --------------------------- */

    @PostMapping("/message/send")
    public ResponseEntity<?> sendMessage(@RequestBody SendRequest req) {
        try {
            if (req == null || req.senderId == null || req.receiverId == null || req.plaintext == null) {
                return ResponseEntity.badRequest().body("senderId, receiverId and plaintext required");
            }

            KeyPair senderKP = keyStore.get(req.senderId);
            KeyPair receiverKP = keyStore.get(req.receiverId);
            if (senderKP == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No keypair for senderId: " + req.senderId);
            if (receiverKP == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No keypair for receiverId: " + req.receiverId);

            // 1) Generate AES-256 session key
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(AES_KEY_BITS, RANDOM);
            SecretKey aesKey = kg.generateKey();
            byte[] rawAes = aesKey.getEncoded();

            // 2) Generate random IV (12 bytes)
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            RANDOM.nextBytes(iv);

            // 3) AES-GCM encrypt plaintext
            byte[] plaintextBytes = req.plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            byte[] ciphertext = aesCipher.doFinal(plaintextBytes);

            // 4) Encrypt (wrap) AES key with receiver's RSA public key (OAEP SHA-256)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, receiverKP.getPublic());
            byte[] encryptedAesKey = rsaCipher.doFinal(rawAes);

            // 5) timestamp and nonce
            long timestamp = System.currentTimeMillis();
            byte[] nonceBytes = new byte[16];
            RANDOM.nextBytes(nonceBytes);
            String nonceB64 = Base64.getEncoder().encodeToString(nonceBytes);

            // 6) Build canonical payload string for signing (fixed order)
            String ivB64 = Base64.getEncoder().encodeToString(iv);
            String encryptedAesKeyB64 = Base64.getEncoder().encodeToString(encryptedAesKey);
            String ciphertextB64 = Base64.getEncoder().encodeToString(ciphertext);

            String canonical = String.join("|",
                    req.senderId,
                    req.receiverId,
                    Long.toString(timestamp),
                    nonceB64,
                    ivB64,
                    encryptedAesKeyB64,
                    ciphertextB64
            );

            // 7) Sign canonical bytes with sender private key
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(senderKP.getPrivate(), RANDOM);
            signer.update(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] signature = signer.sign();
            String signatureB64 = Base64.getEncoder().encodeToString(signature);

            // 8) Build response (including raw AES key for demo — WARNING: insecure)
            SendResponse resp = new SendResponse();
            resp.senderId = req.senderId;
            resp.receiverId = req.receiverId;
            resp.timestamp = timestamp;
            resp.nonce = nonceB64;
            resp.iv = ivB64;
            resp.encryptedAesKey = encryptedAesKeyB64;
            resp.ciphertext = ciphertextB64;
            resp.signature = signatureB64;
            resp.aesKey = Base64.getEncoder().encodeToString(rawAes); // demo-only
            resp.aesAlgorithm = "AES/GCM/NoPadding";
            resp.rsaKeyEnc = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            resp.signatureAlgorithm = "SHA256withRSA";

            // 9) Store package for receiver to fetch
            String mapKey = mapKey(req.senderId, req.receiverId);
            messageStore.put(mapKey, resp);

            return ResponseEntity.ok(resp);

        } catch (GeneralSecurityException ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Crypto error: " + ex.getMessage());
        }
    }

    /* ---------------------------
       GET latest package for sender->receiver
       --------------------------- */

    @GetMapping("/message/latest")
    public ResponseEntity<?> getLatestMessage(@RequestParam String senderId, @RequestParam String receiverId, HttpServletRequest request) {
        rateLimitCheck(request);
        if (senderId == null || receiverId == null) return ResponseEntity.badRequest().body("senderId and receiverId required");
        String key = mapKey(senderId, receiverId);
        SendResponse resp = messageStore.get(key);
        if (resp == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "No message stored for this sender->receiver"));
        return ResponseEntity.ok(resp);
    }

    /* ---------------------------
       Receive: verify canonical payload + timestamp + nonce-replay-check + unwrap + decrypt
       --------------------------- */

    @PostMapping("/message/receive")
    public ResponseEntity<?> receiveMessage(@RequestBody ReceiveRequest req) {
        try {
            if (req == null || req.senderId == null || req.receiverId == null
                    || req.encryptedAesKey == null || req.iv == null || req.ciphertext == null
                    || req.signature == null || req.timestamp == null || req.nonce == null) {
                return ResponseEntity.badRequest().body("senderId, receiverId, encryptedAesKey, iv, ciphertext, signature, timestamp, nonce required");
            }

            KeyPair senderKP = keyStore.get(req.senderId);
            KeyPair receiverKP = keyStore.get(req.receiverId);
            if (senderKP == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No keypair for senderId: " + req.senderId);
            if (receiverKP == null) return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No keypair for receiverId: " + req.receiverId);

            // Recreate canonical string
            String canonical = String.join("|",
                    req.senderId,
                    req.receiverId,
                    Long.toString(req.timestamp),
                    req.nonce,
                    req.iv,
                    req.encryptedAesKey,
                    req.ciphertext
            );

            // Verify signature with sender public key
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(senderKP.getPublic());
            verifier.update(canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] sigBytes = Base64.getDecoder().decode(req.signature);
            boolean signatureValid = verifier.verify(sigBytes);

            if (!signatureValid) {
                ReceiveResponse r = new ReceiveResponse();
                r.verified = false;
                r.error = "Signature verification failed";
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(r);
            }

            // Check timestamp freshness
            long now = System.currentTimeMillis();
            if (Math.abs(now - req.timestamp) > WINDOW_MILLIS) {
                ReceiveResponse r = new ReceiveResponse();
                r.verified = false;
                r.error = "Timestamp outside allowed window";
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(r);
            }

            // Check nonce replay
            if (usedNonces.putIfAbsent(req.nonce, now) != null) {
                ReceiveResponse r = new ReceiveResponse();
                r.verified = false;
                r.error = "Nonce already used (replay detected)";
                return ResponseEntity.status(HttpStatus.CONFLICT).body(r);
            }

            // Decrypt AES key with receiver's private RSA key (OAEP)
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            rsaCipher.init(Cipher.DECRYPT_MODE, receiverKP.getPrivate());
            byte[] aesKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(req.encryptedAesKey));

            // AES-GCM decrypt ciphertext
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, Base64.getDecoder().decode(req.iv));
            aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec, gcmSpec);
            byte[] plaintextBytes = aesCipher.doFinal(Base64.getDecoder().decode(req.ciphertext));

            String plaintext = new String(plaintextBytes, java.nio.charset.StandardCharsets.UTF_8);

            ReceiveResponse r = new ReceiveResponse();
            r.verified = true;
            r.plaintext = plaintext;
            return ResponseEntity.ok(r);

        } catch (AEADBadTagException ex) {
            ReceiveResponse r = new ReceiveResponse();
            r.verified = true;
            r.error = "AES-GCM authentication failed (bad tag / tampered ciphertext).";
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(r);
        } catch (GeneralSecurityException ex) {
            ReceiveResponse r = new ReceiveResponse();
            r.error = "Crypto error: " + ex.getMessage();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(r);
        } catch (IllegalArgumentException ex) {
            ReceiveResponse r = new ReceiveResponse();
            r.error = "Base64 decode error: " + ex.getMessage();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(r);
        }
    }

    /* ---------------------------
       Helper methods & DTOs
       --------------------------- */

    private String mapKey(String senderId, String receiverId) {
        return senderId + "->" + receiverId;
    }

    public static class SendRequest {
        public String senderId;
        public String receiverId;
        public String plaintext;
        public SendRequest() {}
    }

    public static class SendResponse {
        public String senderId;
        public String receiverId;
        public Long timestamp;
        public String nonce;
        public String iv;              // Base64
        public String encryptedAesKey; // Base64
        public String ciphertext;      // Base64
        public String signature;       // Base64
        public String aesKey;          // Base64 (demo-only; do not expose in production)
        public String aesAlgorithm;
        public String rsaKeyEnc;
        public String signatureAlgorithm;
        public SendResponse() {}
    }

    public static class ReceiveRequest {
        public String senderId;
        public String receiverId;
        public Long timestamp;
        public String nonce;
        public String encryptedAesKey; // Base64
        public String iv;              // Base64
        public String ciphertext;      // Base64
        public String signature;       // Base64
        public ReceiveRequest() {}
    }

    public static class ReceiveResponse {
        public boolean verified;
        public String plaintext;
        public String error;
        public ReceiveResponse() {}
    }
}
