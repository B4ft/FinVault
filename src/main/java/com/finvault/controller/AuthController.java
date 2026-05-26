package com.finvault.controller;

import com.finvault.model.User;
import com.finvault.service.JwtService;
import com.finvault.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.math.BigDecimal;
import java.sql.*;
import java.util.Optional;
import java.util.UUID;

/**
 * Authentication Controller
 *
 * VULNERABILITY 1: SQL Injection in forgot-password endpoint.
 * Raw JDBC with string concatenation - no prepared statements.
 */
@Controller
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private DataSource dataSource;

    // -------------------------------------------------------------------------
    // LOGIN
    // -------------------------------------------------------------------------

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String error, Model model) {
        model.addAttribute("error", error);
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletResponse response,
                        Model model) {
        Optional<User> userOpt = userService.findByUsername(username);

        if (userOpt.isPresent() && userOpt.get().getPassword().equals(password)) {
            User user = userOpt.get();
            String token = jwtService.generateToken(user.getUsername(), user.getRole(), user.getId());

            Cookie cookie = new Cookie("jwt-token", token);
            cookie.setPath("/");
            cookie.setMaxAge(86400);
            // VULNERABILITY: HttpOnly not set - token accessible via JavaScript
            // cookie.setHttpOnly(true); // intentionally commented out
            response.addCookie(cookie);

            return "redirect:/dashboard";
        }

        model.addAttribute("error", "Invalid username or password");
        return "login";
    }

    // -------------------------------------------------------------------------
    // REGISTER
    // -------------------------------------------------------------------------

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam String email,
                           @RequestParam(required = false) String fullName,
                           Model model) {
        try {
            User user = new User();
            user.setUsername(username);
            user.setPassword(password); // VULNERABILITY: plaintext password storage
            user.setEmail(email);
            user.setFullName(fullName != null ? fullName : username);
            user.setPhone("");
            user.setRole("USER");
            user.setBalance(BigDecimal.ZERO);
            user.setAccountNumber("ACC-" + String.format("%05d", (int)(Math.random() * 99999)));
            userService.save(user);
            return "redirect:/auth/login?registered=true";
        } catch (Exception e) {
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
        }
    }

    // -------------------------------------------------------------------------
    // FORGOT PASSWORD - VULNERABLE TO SQL INJECTION
    // -------------------------------------------------------------------------

    @GetMapping("/forgot-password")
    public String forgotPasswordPage() {
        return "forgot-password";
    }

    /**
     * VULNERABILITY: SQL Injection via raw JDBC string concatenation.
     *
     * Example exploits:
     *   Email: ' OR '1'='1          -> returns all users
     *   Email: ' UNION SELECT username,password,email,full_name,phone,role,balance,account_number,id FROM users--
     *
     * The result is reflected on the page: "Reset link sent to: [email]"
     * Use UNION-based injection to extract data that appears in the response.
     */
    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestParam String email, Model model) {
        String resultEmail = email;
        String queryResult = null;
        boolean found = false;

        try (Connection connection = dataSource.getConnection()) {
            // VULNERABILITY: Raw string concatenation - SQL Injection
            String query = "SELECT * FROM users WHERE email = '" + email + "'";

            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                found = true;
                // If union injection, the "email" column will contain injected data
                try {
                    resultEmail = rs.getString("email");
                    // For UNION injections, extract what was injected
                    queryResult = "User found: " + rs.getString(1) + " | " + rs.getString(3);
                } catch (Exception ex) {
                    queryResult = null;
                }
            }

            // Show what was "returned" - reflects injection output
            model.addAttribute("submitted", true);
            model.addAttribute("email", email); // reflects raw input (also XSS vector)
            model.addAttribute("queryResult", queryResult);
            model.addAttribute("sqlQuery", query); // Show the raw SQL for educational purposes
            model.addAttribute("found", found);

        } catch (SQLException e) {
            model.addAttribute("submitted", true);
            model.addAttribute("email", email);
            model.addAttribute("sqlError", e.getMessage());
            model.addAttribute("sqlQuery", "SELECT * FROM users WHERE email = '" + email + "'");
        }

        return "forgot-password";
    }

    // -------------------------------------------------------------------------
    // LOGOUT
    // -------------------------------------------------------------------------

    @GetMapping("/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("jwt-token", "");
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/auth/login?logout=true";
    }
}
