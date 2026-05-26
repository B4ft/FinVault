package com.finvault.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.stereotype.Service;

import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * INTENTIONALLY VULNERABLE JWT Service for educational purposes.
 *
 * Vulnerabilities:
 * 1. Accepts "alg:none" tokens - anyone can forge a token with no signature
 * 2. Uses weak secret "secret" - trivially crackable with hashcat / jwt-tool
 * 3. Role is embedded in JWT and trusted without DB verification - privilege escalation
 */
@Service
public class JwtService {

    // VULNERABILITY: Weak, hardcoded secret
    private static final String SECRET = "secret";

    public String generateToken(String username, String role, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", role);
        claims.put("userId", userId);

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000L))
                .signWith(SignatureAlgorithm.HS256, SECRET.getBytes())
                .compact();
    }

    /**
     * VULNERABILITY: Accepts alg:none tokens with no signature verification.
     * An attacker can create a token like:
     *   header: {"alg":"none","typ":"JWT"}
     *   payload: {"sub":"admin","role":"ADMIN","userId":1}
     *   signature: (empty)
     */
    public boolean validateToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return false;

            String headerJson = new String(Base64.getUrlDecoder().decode(
                padBase64(parts[0])
            ));

            // VULNERABILITY: Accept unsigned tokens if alg is "none"
            if (headerJson.contains("\"alg\":\"none\"") || headerJson.contains("\"alg\": \"none\"")) {
                // Accept the token with no signature check
                return true;
            }

            // Normal validation with weak secret
            Jwts.parser()
                .setSigningKey(SECRET.getBytes())
                .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;

            String payloadJson = new String(Base64.getUrlDecoder().decode(
                padBase64(parts[1])
            ));

            // Parse "sub" from JSON manually (works for alg:none too)
            return extractJsonField(payloadJson, "sub");
        } catch (Exception e) {
            return null;
        }
    }

    public String extractRole(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return "USER";

            String payloadJson = new String(Base64.getUrlDecoder().decode(
                padBase64(parts[1])
            ));

            String role = extractJsonField(payloadJson, "role");
            return role != null ? role : "USER";
        } catch (Exception e) {
            return "USER";
        }
    }

    public Long extractUserId(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length < 2) return null;

            String payloadJson = new String(Base64.getUrlDecoder().decode(
                padBase64(parts[1])
            ));

            String userIdStr = extractJsonField(payloadJson, "userId");
            if (userIdStr == null) return null;
            // Handle both "userId":2 (number) and "userId":"2" (string)
            userIdStr = userIdStr.replace("\"", "").trim();
            return Long.parseLong(userIdStr);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractJsonField(String json, String field) {
        try {
            String search = "\"" + field + "\"";
            int idx = json.indexOf(search);
            if (idx < 0) return null;

            int colonIdx = json.indexOf(":", idx);
            if (colonIdx < 0) return null;

            int start = colonIdx + 1;
            // Skip whitespace
            while (start < json.length() && json.charAt(start) == ' ') start++;

            // Check if value is a string (starts with ")
            if (json.charAt(start) == '"') {
                int end = json.indexOf('"', start + 1);
                return json.substring(start + 1, end);
            } else {
                // Numeric or boolean value
                int end = start;
                while (end < json.length() && json.charAt(end) != ',' && json.charAt(end) != '}') end++;
                return json.substring(start, end).trim();
            }
        } catch (Exception e) {
            return null;
        }
    }

    private String padBase64(String base64) {
        switch (base64.length() % 4) {
            case 2: return base64 + "==";
            case 3: return base64 + "=";
            default: return base64;
        }
    }
}
