package com.finvault.controller;

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

/**
 * Admin Controller
 *
 * VULNERABILITY: JWT Role Forgery (ties into JWT misconfiguration)
 * The admin check relies solely on the JWT claim - no DB verification.
 * An attacker can forge a JWT with "role":"ADMIN" to gain admin access.
 *
 * Also hosts the internal admin-data endpoint that demonstrates SSRF impact.
 */
@Controller
public class AdminController {

    @Autowired
    private UserService userService;

    // -------------------------------------------------------------------------
    // ADMIN PANEL - Protected only by JWT role claim (forgeable)
    // -------------------------------------------------------------------------

    @GetMapping("/admin")
    public String adminPanel(HttpServletRequest request, Model model) {
        String role = (String) request.getAttribute("role");

        // VULNERABILITY: Checks JWT role claim directly - can be bypassed by forging JWT
        if (!"ADMIN".equalsIgnoreCase(role)) {
            model.addAttribute("error", "Access denied. Admin role required.");
            model.addAttribute("hint",
                "Hint: Try forging a JWT with role=ADMIN. " +
                "Use alg:none or crack the weak secret 'secret' with hashcat.");
            model.addAttribute("username", request.getAttribute("username"));
            model.addAttribute("role", role);
            model.addAttribute("userId", request.getAttribute("userId"));
            return "admin";
        }

        List<User> users = userService.findAll();
        model.addAttribute("users", users);
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("role", role);
        model.addAttribute("userId", request.getAttribute("userId"));
        model.addAttribute("isAdmin", true);

        return "admin";
    }

    // -------------------------------------------------------------------------
    // INTERNAL ENDPOINT - Accessible from localhost only (for SSRF demo)
    // -------------------------------------------------------------------------

    /**
     * This endpoint is "protected" only by network controls (localhost-only).
     * It's exposed at /internal/admin-data and returns sensitive internal data.
     *
     * In a real deployment, firewall rules would block external access.
     * However, SSRF via /documents/fetch allows an external user to reach it
     * by routing requests through the server itself.
     *
     * Exploit: POST /documents/fetch with url=http://localhost:8080/internal/admin-data
     */
    @GetMapping("/internal/admin-data")
    @ResponseBody
    public ResponseEntity<?> internalAdminData(HttpServletRequest request) {
        // In production this would check request.getRemoteAddr() == "127.0.0.1"
        // For demo purposes it's accessible from anywhere (rely on the SecurityConfig permitAll)

        Map<String, Object> data = new HashMap<>();
        data.put("endpoint", "INTERNAL ADMIN DATA - CONFIDENTIAL");
        data.put("warning", "This endpoint should only be accessible from localhost!");
        data.put("ssrfNote", "You reached this via SSRF through /documents/fetch");

        // Sensitive internal data exposed via SSRF
        Map<String, Object> secrets = new HashMap<>();
        secrets.put("adminUsername", "admin");
        secrets.put("adminPassword", "admin123");
        secrets.put("dbConnectionString", "jdbc:h2:mem:finvault;user=sa;password=finvault_db_pass");
        secrets.put("internalApiKey", "fv-internal-key-9a8b7c6d5e4f");
        secrets.put("awsAccessKeyId", "AKIAIOSFODNN7EXAMPLE");
        secrets.put("awsSecretKey", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        secrets.put("jwtSecret", "secret");
        secrets.put("h2ConsoleUrl", "http://localhost:8080/h2-console");

        Map<String, Object> systemInfo = new HashMap<>();
        systemInfo.put("javaVersion", System.getProperty("java.version"));
        systemInfo.put("osName", System.getProperty("os.name"));
        systemInfo.put("userHome", System.getProperty("user.home"));
        systemInfo.put("serverPort", "8080");

        List<User> allUsers = userService.findAll();
        Map<String, Object> userSummary = new HashMap<>();
        for (User u : allUsers) {
            Map<String, Object> uData = new HashMap<>();
            uData.put("password", u.getPassword());
            uData.put("email", u.getEmail());
            uData.put("balance", u.getBalance());
            uData.put("accountNumber", u.getAccountNumber());
            userSummary.put(u.getUsername(), uData);
        }

        data.put("secrets", secrets);
        data.put("systemInfo", systemInfo);
        data.put("allUsers", userSummary);

        return ResponseEntity.ok(data);
    }

    // -------------------------------------------------------------------------
    // API: List all users (admin only via JWT - bypassable)
    // -------------------------------------------------------------------------

    @GetMapping("/api/admin/users")
    @ResponseBody
    public ResponseEntity<?> listUsers(HttpServletRequest request) {
        String role = (String) request.getAttribute("role");
        if (!"ADMIN".equalsIgnoreCase(role)) {
            return ResponseEntity.status(403).body(Map.of("error", "Forbidden - admin only"));
        }
        return ResponseEntity.ok(userService.findAll());
    }
}
