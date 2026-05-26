package com.finvault.controller;

import com.finvault.model.Transaction;
import com.finvault.model.User;
import com.finvault.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * User Controller
 *
 * VULNERABILITY 2: IDOR (Insecure Direct Object Reference)
 * No authorization checks on profile endpoints.
 * Any authenticated user can read/update ANY user's profile by changing the {id}.
 */
@Controller
public class UserController {

    @Autowired
    private UserService userService;

    // -------------------------------------------------------------------------
    // DASHBOARD
    // -------------------------------------------------------------------------

    @GetMapping("/dashboard")
    public String dashboard(HttpServletRequest request, Model model) {
        Long userId = (Long) request.getAttribute("userId");
        String username = (String) request.getAttribute("username");
        String role = (String) request.getAttribute("role");

        Optional<User> userOpt = userService.findById(userId);
        if (userOpt.isEmpty()) {
            return "redirect:/auth/login";
        }

        User user = userOpt.get();
        List<Transaction> transactions = userService.getAllTransactions(userId);

        model.addAttribute("user", user);
        model.addAttribute("transactions", transactions);
        model.addAttribute("username", username);
        model.addAttribute("role", role);
        model.addAttribute("userId", userId);

        return "dashboard";
    }

    // -------------------------------------------------------------------------
    // PROFILE PAGE (IDOR - URL shows the ID clearly)
    // -------------------------------------------------------------------------

    @GetMapping("/profile/{id}")
    public String profilePage(@PathVariable Long id,
                              HttpServletRequest request,
                              Model model) {
        // VULNERABILITY: No check that request.getAttribute("userId").equals(id)
        // Any authenticated user can view any profile by changing the ID in the URL

        Optional<User> userOpt = userService.findById(id);
        if (userOpt.isEmpty()) {
            model.addAttribute("error", "User not found");
            return "profile";
        }

        User profileUser = userOpt.get();
        String currentRole = (String) request.getAttribute("role");
        Long currentUserId = (Long) request.getAttribute("userId");

        model.addAttribute("profileUser", profileUser);
        model.addAttribute("currentUserId", currentUserId);
        model.addAttribute("role", currentRole);
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("userId", currentUserId);
        // VULNERABILITY: Explicitly passing the target ID to show in forms
        model.addAttribute("targetId", id);

        return "profile";
    }

    // -------------------------------------------------------------------------
    // API: GET USER - VULNERABLE TO IDOR
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: No authorization check.
     * GET /api/users/1 returns admin's full profile (including password) to any user.
     */
    @GetMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> getUser(@PathVariable Long id, HttpServletRequest request) {
        // No check: if (!request.getAttribute("userId").equals(id)) return 403;
        Optional<User> userOpt = userService.findById(id);

        if (userOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        User user = userOpt.get();
        Map<String, Object> response = new HashMap<>();
        response.put("id", user.getId());
        response.put("username", user.getUsername());
        response.put("password", user.getPassword()); // VULNERABILITY: returns plaintext password
        response.put("email", user.getEmail());
        response.put("fullName", user.getFullName());
        response.put("phone", user.getPhone());
        response.put("role", user.getRole());
        response.put("balance", user.getBalance());
        response.put("accountNumber", user.getAccountNumber());

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // API: UPDATE PROFILE - VULNERABLE TO IDOR
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: No authorization check.
     * PUT /api/users/1/profile allows any user to update the admin's profile.
     */
    @PutMapping("/api/users/{id}/profile")
    @ResponseBody
    public ResponseEntity<?> updateProfile(@PathVariable Long id,
                                           @RequestBody Map<String, String> body,
                                           HttpServletRequest request) {
        // VULNERABILITY: No check that the current user owns this profile
        // Should be: if (!request.getAttribute("userId").equals(id)) return 403;

        String fullName = body.get("fullName");
        String email    = body.get("email");
        String phone    = body.get("phone");

        userService.updateProfile(id, fullName, email, phone);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Profile updated successfully for user ID: " + id);
        response.put("updatedId", id);

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // API: CHANGE PASSWORD - VULNERABLE TO IDOR
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: No authorization check.
     * PUT /api/users/1/password allows any user to change the admin's password.
     */
    @PutMapping("/api/users/{id}/password")
    @ResponseBody
    public ResponseEntity<?> changePassword(@PathVariable Long id,
                                            @RequestBody Map<String, String> body,
                                            HttpServletRequest request) {
        // VULNERABILITY: No check that the current user owns this account
        // No current-password verification either

        String newPassword = body.get("newPassword");
        if (newPassword == null || newPassword.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "New password required"));
        }

        userService.updatePassword(id, newPassword);

        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Password changed successfully for user ID: " + id);
        response.put("updatedId", id);

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // RESTORE SESSION - INSECURE DESERIALIZATION
    // -------------------------------------------------------------------------

    /**
     * VULNERABILITY: Insecure Deserialization.
     * Accepts Base64-encoded Java serialized objects and deserializes them with no filtering.
     * With commons-collections 3.2.1 on the classpath, ysoserial payloads achieve RCE.
     *
     * Generate payload: java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" | base64
     * POST /api/restore-session with body: {"sessionData": "<base64>"}
     */
    @PostMapping("/api/restore-session")
    @ResponseBody
    public ResponseEntity<?> restoreSession(@RequestBody(required = false) Map<String, String> body,
                                            @CookieValue(value = "remember-session", required = false) String cookieData,
                                            HttpServletRequest request) {
        String base64Data = null;

        if (body != null && body.containsKey("sessionData")) {
            base64Data = body.get("sessionData");
        } else if (cookieData != null) {
            base64Data = cookieData;
        }

        if (base64Data == null || base64Data.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "No session data provided"));
        }

        try {
            // VULNERABILITY: Unsafe deserialization with no filtering
            byte[] data = java.util.Base64.getDecoder().decode(base64Data);
            java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(data);
            java.io.ObjectInputStream ois = new java.io.ObjectInputStream(bais);
            Object obj = ois.readObject(); // UNSAFE - executes arbitrary code with ysoserial

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Session restored",
                "sessionType", obj.getClass().getName()
            ));
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of(
                "error", "Session restoration failed: " + e.getMessage(),
                "hint", "Try a ysoserial CommonsCollections1 payload"
            ));
        }
    }
}
