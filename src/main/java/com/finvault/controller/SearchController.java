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

import java.math.BigDecimal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Search Controller
 *
 * VULNERABILITY 3: Cross-Site Scripting (XSS)
 * - Reflected XSS: search query rendered via innerHTML
 * - Stored XSS: transaction descriptions stored and rendered via innerHTML
 */
@Controller
public class SearchController {

    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public String searchPage(@RequestParam(required = false) String q,
                             HttpServletRequest request,
                             Model model) {
        Long userId = (Long) request.getAttribute("userId");
        String username = (String) request.getAttribute("username");
        String role = (String) request.getAttribute("role");

        model.addAttribute("username", username);
        model.addAttribute("role", role);
        model.addAttribute("userId", userId);
        model.addAttribute("query", q); // Passed to template, rendered unsafely in JS

        if (q != null && !q.isEmpty()) {
            List<Transaction> results = userService.searchTransactions(userId, q);
            model.addAttribute("results", results);
            model.addAttribute("resultCount", results.size());
        }

        return "search";
    }

    /**
     * API endpoint for search - returns JSON with raw description (for stored XSS)
     * Results rendered via innerHTML in the client
     */
    @GetMapping("/api/search")
    @ResponseBody
    public ResponseEntity<?> searchApi(@RequestParam String q,
                                       HttpServletRequest request) {
        Long userId = (Long) request.getAttribute("userId");
        List<Transaction> results = userService.searchTransactions(userId, q);

        return ResponseEntity.ok(Map.of(
            "query", q,       // reflected back for XSS
            "results", results,
            "count", results.size()
        ));
    }

    /**
     * Add a transaction with a custom description (stored XSS vector)
     * POST /api/transactions/add
     * body: { description: "<script>alert(1)</script>", amount: 10.00, type: "DEBIT" }
     */
    @PostMapping("/api/transactions/add")
    @ResponseBody
    public ResponseEntity<?> addTransaction(@RequestBody Map<String, Object> body,
                                            HttpServletRequest request) {
        Long userId = (Long) request.getAttribute("userId");

        // VULNERABILITY: Description stored without sanitization (stored XSS)
        String description = (String) body.get("description");
        BigDecimal amount  = new BigDecimal(body.get("amount").toString());
        String type        = (String) body.getOrDefault("type", "DEBIT");

        userService.addTransaction(userId, description, amount, type);

        return ResponseEntity.ok(Map.of(
            "success", true,
            "message", "Transaction added: " + description // also reflected
        ));
    }
}
