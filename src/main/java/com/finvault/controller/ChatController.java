package com.finvault.controller;

import com.finvault.model.Transaction;
import com.finvault.service.ChatService;
import com.finvault.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Chat Controller
 *
 * VULNERABILITY 8: Prompt Injection
 * The AI assistant is vulnerable to direct and indirect prompt injection.
 */
@Controller
public class ChatController {

    @Autowired
    private ChatService chatService;

    @Autowired
    private UserService userService;

    @GetMapping("/chat")
    public String chatPage(HttpServletRequest request, Model model) {
        model.addAttribute("username", request.getAttribute("username"));
        model.addAttribute("role", request.getAttribute("role"));
        model.addAttribute("userId", request.getAttribute("userId"));
        return "chat";
    }

    /**
     * Process chat message.
     * Vulnerable to prompt injection - passes raw user input and recent transactions
     * (which may contain injected instructions) to the AI service.
     */
    @PostMapping("/api/chat")
    @ResponseBody
    public ResponseEntity<?> chat(@RequestBody Map<String, String> body,
                                  HttpServletRequest request) {
        Long userId = (Long) request.getAttribute("userId");
        String message = body.get("message");

        if (message == null || message.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Message required"));
        }

        // VULNERABILITY: Loads recent transactions (may contain injected instructions)
        // and passes them to the AI without sanitization (indirect prompt injection)
        List<Transaction> recentTransactions = userService.getRecentTransactionsForChat(userId);

        // Process message (vulnerable to injection via message OR transaction descriptions)
        String response = chatService.processMessage(message, recentTransactions);

        return ResponseEntity.ok(Map.of(
            "message", message,
            "response", response,
            "transactionsChecked", recentTransactions.size()
        ));
    }
}
