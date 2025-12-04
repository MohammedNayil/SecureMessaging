package com.project1.demo;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    @PostMapping
    public ResponseEntity<String> receiveMessage(@RequestBody Map<String, String> payload) {
        // Payload contains: ciphertext, iv, salt
        String ciphertext = payload.get("ciphertext");
        String iv = payload.get("iv");
        String salt = payload.get("salt");

        // For demo, we just print it to the console
        System.out.println("Received AES-GCM message:");
        System.out.println("Ciphertext: " + ciphertext);
        System.out.println("IV: " + iv);
        System.out.println("Salt: " + salt);

        // You could store it in a DB here or pass it to a decryption routine

        return new ResponseEntity<>("Message received", HttpStatus.OK);
    }
}