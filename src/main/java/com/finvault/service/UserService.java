package com.finvault.service;

import com.finvault.model.Transaction;
import com.finvault.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private final RowMapper<User> userRowMapper = (rs, rowNum) -> {
        User u = new User();
        u.setId(rs.getLong("id"));
        u.setUsername(rs.getString("username"));
        u.setPassword(rs.getString("password"));
        u.setEmail(rs.getString("email"));
        u.setFullName(rs.getString("full_name"));
        u.setPhone(rs.getString("phone"));
        u.setRole(rs.getString("role"));
        u.setBalance(rs.getBigDecimal("balance"));
        u.setAccountNumber(rs.getString("account_number"));
        return u;
    };

    private final RowMapper<Transaction> txRowMapper = (rs, rowNum) -> {
        Transaction t = new Transaction();
        t.setId(rs.getLong("id"));
        t.setUserId(rs.getLong("user_id"));
        t.setDescription(rs.getString("description"));
        t.setAmount(rs.getBigDecimal("amount"));
        t.setTransactionType(rs.getString("transaction_type"));
        t.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        return t;
    };

    public Optional<User> findByUsername(String username) {
        try {
            List<User> users = jdbcTemplate.query(
                "SELECT * FROM users WHERE username = ?", userRowMapper, username);
            return users.isEmpty() ? Optional.empty() : Optional.of(users.get(0));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<User> findById(Long id) {
        try {
            List<User> users = jdbcTemplate.query(
                "SELECT * FROM users WHERE id = ?", userRowMapper, id);
            return users.isEmpty() ? Optional.empty() : Optional.of(users.get(0));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<User> findAll() {
        return jdbcTemplate.query("SELECT * FROM users", userRowMapper);
    }

    public void save(User user) {
        jdbcTemplate.update(
            "INSERT INTO users (username, password, email, full_name, phone, role, balance, account_number) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            user.getUsername(), user.getPassword(), user.getEmail(),
            user.getFullName(), user.getPhone(), user.getRole(),
            user.getBalance(), user.getAccountNumber()
        );
    }

    // VULNERABLE: No authorization check — any user can update any profile
    public void updateProfile(Long id, String fullName, String email, String phone) {
        jdbcTemplate.update(
            "UPDATE users SET full_name = ?, email = ?, phone = ? WHERE id = ?",
            fullName, email, phone, id
        );
    }

    // VULNERABLE: No authorization check — any user can change any password
    public void updatePassword(Long id, String newPassword) {
        jdbcTemplate.update(
            "UPDATE users SET password = ? WHERE id = ?",
            newPassword, id
        );
    }

    public List<Transaction> getTransactionsByUserId(Long userId) {
        return jdbcTemplate.query(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC",
            txRowMapper, userId
        );
    }

    public List<Transaction> searchTransactions(Long userId, String query) {
        // Safe query for filtering, but results rendered unsafely in the template (XSS)
        return jdbcTemplate.query(
            "SELECT * FROM transactions WHERE user_id = ? AND LOWER(description) LIKE LOWER(?)",
            txRowMapper, userId, "%" + query + "%"
        );
    }

    public List<Transaction> getAllTransactions(Long userId) {
        return jdbcTemplate.query(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
            txRowMapper, userId
        );
    }

    public void addTransaction(Long userId, String description, java.math.BigDecimal amount, String type) {
        jdbcTemplate.update(
            "INSERT INTO transactions (user_id, description, amount, transaction_type) VALUES (?, ?, ?, ?)",
            userId, description, amount, type
        );
    }

    public List<Transaction> getRecentTransactionsForChat(Long userId) {
        return jdbcTemplate.query(
            "SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
            txRowMapper, userId
        );
    }
}
