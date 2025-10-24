package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TransferController {

    public static class TransferReq {
        public int fromUserId;
        public int toUserId;
        public double amount;
    }

    @PostMapping("/api/transfer")
    public ResponseEntity<?> transfer(@RequestBody TransferReq req) {
        if (req.amount <= 0) {
            return ResponseEntity.badRequest().body(Map.of("amount", "Transfer amount must be positive"));
        }
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
