package com.finvault.filter;

import com.finvault.service.JwtService;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * JWT Authentication Filter.
 * Reads 'jwt-token' cookie and validates using JwtService.
 * Intentionally weak - trusts JWT claims without DB verification.
 */
@Component
public class JwtAuthFilter implements Filter {

    @Autowired
    private JwtService jwtService;

    private static final String[] PUBLIC_PATHS = {
        "/auth/", "/static/", "/css/", "/js/", "/h2-console", "/internal/"
    };

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest request  = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String path = request.getRequestURI();

        // Allow public paths without authentication
        for (String pub : PUBLIC_PATHS) {
            if (path.startsWith(pub)) {
                chain.doFilter(req, res);
                return;
            }
        }

        // Allow root redirect
        if (path.equals("/")) {
            chain.doFilter(req, res);
            return;
        }

        // Extract JWT from cookie
        String token = extractTokenFromCookie(request);

        if (token != null && jwtService.validateToken(token)) {
            // VULNERABILITY: Role is trusted directly from JWT without DB check
            String username = jwtService.extractUsername(token);
            String role     = jwtService.extractRole(token);
            Long   userId   = jwtService.extractUserId(token);

            request.setAttribute("username", username);
            request.setAttribute("role", role);
            request.setAttribute("userId", userId);
            request.setAttribute("jwtToken", token);

            chain.doFilter(req, res);
        } else {
            // No valid token — redirect to login
            response.sendRedirect("/auth/login?error=session");
        }
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;

        for (Cookie cookie : cookies) {
            if ("jwt-token".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
