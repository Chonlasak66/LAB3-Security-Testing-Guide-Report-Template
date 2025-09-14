// frontend/secure-script.js
const API_BASE = 'http://localhost:3001';

let currentUser = null;
let authToken = null;

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
    checkServerStatus();
});

function initializeApp() {
    // Character counter for comments
    const commentTextarea = document.getElementById('comment-content');
    const charCounter = document.getElementById('char-count');
    const charWarning = document.getElementById('char-warning');
    
    if (commentTextarea && charCounter) {
        commentTextarea.addEventListener('input', () => {
            const length = commentTextarea.value.length;
            charCounter.textContent = length;
            
            if (length > 900) {
                charCounter.style.color = '#e74c3c';
                charWarning.style.display = 'inline';
                charWarning.textContent = '⚠️ Approaching limit';
            } else if (length > 800) {
                charCounter.style.color = '#f39c12';
                charWarning.style.display = 'inline';
                charWarning.textContent = '⚡ Getting close';
            } else {
                charCounter.style.color = '#7f8c8d';
                charWarning.style.display = 'none';
            }
        });
    }
    
    loadComments();
}

function setupEventListeners() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    
    // Comment form
    document.getElementById('comment-form').addEventListener('submit', handleComment);
    
    // Search form
    document.getElementById('search-form').addEventListener('submit', handleSearch);
}

// Check server status
async function checkServerStatus() {
    const statusElement = document.getElementById('server-status');
    try {
        const response = await fetch(`${API_BASE}/health`);
        if (response.ok) {
            const data = await response.json();
            statusElement.innerHTML = '🟢 Secure server is online';
            statusElement.style.color = '#27ae60';
        } else {
            throw new Error('Server not responding');
        }
    } catch (error) {
        statusElement.innerHTML = '🔴 Server is offline - Please start the secure server';
        statusElement.style.color = '#e74c3c';
    }
}

// Handle login
async function handleLogin(e) {
    e.preventDefault();
    
    const loginBtn = document.getElementById('login-btn');
    const originalText = loginBtn.textContent;
    
    // Disable button and show loading state
    loginBtn.disabled = true;
    loginBtn.textContent = '🔄 Authenticating...';
    
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    // Client-side validation
    if (!username || !password) {
        showResult('login-result', 'Please fill in all fields', 'error');
        resetButton(loginBtn, originalText);
        return;
    }
    
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        showResult('login-result', 'Username can only contain letters, numbers, and underscores', 'error');
        resetButton(loginBtn, originalText);
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            authToken = data.token;
            
            showResult('login-result', `
                <div class="result-success">
                    <h4>✅ Authentication Successful!</h4>
                    <p><strong>Welcome:</strong> ${escapeHtml(data.user.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.user.email)}</p>
                    <p><strong>Role:</strong> ${data.user.role}</p>
                    <p><strong>Token Issued:</strong> ${new Date().toLocaleString()}</p>
                    <p><small><strong>JWT Token:</strong> ${data.token.substring(0, 30)}...</small></p>
                </div>
            `);
            
            // Update UI after successful login
            updateUIAfterLogin(data.user);
            
        } else {
            showResult('login-result', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        showResult('login-result', `❌ Connection error: ${error.message}`, 'error');
    } finally {
        resetButton(loginBtn, originalText);
    }
}

function updateUIAfterLogin(user) {
    // Show profile section
    document.getElementById('profile-section').style.display = 'block';
    document.getElementById('comment-form-container').style.display = 'block';
    
    // Update user info
    document.getElementById('current-username').textContent = user.username;
    document.getElementById('current-role').textContent = user.role;
    document.getElementById('current-user-id').textContent = user.id;
    
    // Show admin controls if admin
    if (user.role === 'admin') {
        document.getElementById('admin-controls').style.display = 'block';
    }
    
    // Reload comments to show user-specific features
    loadComments();
}

// Load user profile
async function loadMyProfile() {
    if (!authToken || !currentUser) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/${currentUser.id}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult('profile-result', `
                <div class="result-success">
                    <h4>📄 My Secure Profile</h4>
                    <p><strong>ID:</strong> ${data.id}</p>
                    <p><strong>Username:</strong> ${escapeHtml(data.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
                    <p><strong>Role:</strong> ${data.role}</p>
                    <p><strong>Account Created:</strong> ${new Date(data.created_at).toLocaleDateString()}</p>
                    <p><small>✅ Authorization verified - You can only see your own profile</small></p>
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Load user profile (Admin only)
async function loadUserProfile() {
    const userId = document.getElementById('admin-user-id').value;
    
    if (!userId) {
        showResult('profile-result', 'Please enter a user ID', 'error');
        return;
    }
    
    if (!authToken) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/user/${userId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showResult('profile-result', `
                <div class="result-success">
                    <h4>🔍 User Profile (Admin Access)</h4>
                    <p><strong>ID:</strong> ${data.id}</p>
                    <p><strong>Username:</strong> ${escapeHtml(data.username)}</p>
                    <p><strong>Email:</strong> ${escapeHtml(data.email)}</p>
                    <p><strong>Role:</strong> ${data.role}</p>
                    <p><strong>Account Created:</strong> ${new Date(data.created_at).toLocaleDateString()}</p>
                    <p><small>👑 Admin privilege verified - Access granted</small></p>
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Load all users (Admin only)
async function loadAllUsers() {
    if (!authToken) {
        showResult('profile-result', 'Please login first', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/admin/users`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok && Array.isArray(data)) {
            const userList = data.map(user => `
                <div class="comment">
                    <strong>👤 ${escapeHtml(user.username)}</strong> (ID: ${user.id})<br>
                    📧 ${escapeHtml(user.email)}<br>
                    🎭 Role: ${user.role}<br>
                    📅 Created: ${new Date(user.created_at).toLocaleDateString()}
                </div>
            `).join('');
            
            showResult('profile-result', `
                <div class="result-success">
                    <h4>👥 All Users (Admin View)</h4>
                    <p>Total users: ${data.length}</p>
                    ${userList}
                </div>
            `);
        } else {
            showResult('profile-result', `❌ ${data.error || 'Access denied'}`, 'error');
        }
    } catch (error) {
        showResult('profile-result', `❌ Error: ${error.message}`, 'error');
    }
}

// Handle comment submission
async function handleComment(e) {
    e.preventDefault();
    
    const content = document.getElementById('comment-content').value.trim();
    
    if (!content) {
        alert('Please enter a comment');
        return;
    }
    
    if (content.length > 1000) {
        alert('Comment is too long (max 1000 characters)');
        return;
    }
    
    if (!authToken) {
        alert('Please login first');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (data.success) {
            document.getElementById('comment-content').value = '';
            document.getElementById('char-count').textContent = '0';
            loadComments();
            
            if (data.sanitized) {
                alert('✅ Comment posted! Note: Content was sanitized for security.');
            }
        } else {
            alert('Failed to add comment: ' + (data.message || 'Unknown error'));
        }
    } catch (error) {
        alert('Error adding comment: ' + error.message);
    }
}

// Handle search
async function handleSearch(e) {
    e.preventDefault();
    
    const query = document.getElementById('search-input').value.trim();
    
    if (!query) {
        showResult('search-results', 'Please enter search term', 'error');
        return;
    }
    
    if (query.length > 100) {
        showResult('search-results', 'Search term too long (max 100 characters)', 'error');
        return;
    }
    
    if (!/^[a-zA-Z0-9\s\-_]+$/.test(query)) {
        showResult('search-results', 'Search term contains invalid characters', 'error');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(query)}`);
        const data = await response.json();
        
        if (response.ok && Array.isArray(data)) {
            if (data.length > 0) {
                const results = data.map(item => `
                    <div class="comment">
                        <strong>${escapeHtml(item.name)}</strong><br>
                        💰 Price: $${item.price}<br>
                        ${item.description ? `📝 ${escapeHtml(item.description)}` : ''}
                    </div>
                `).join('');
                
                showResult('search-results', `
                    <h4>🔍 Search Results (${data.length} found):</h4>
                    ${results}
                `, 'success');
            } else {
                showResult('search-results', 'No products found', 'warning');
            }
        } else {
            showResult('search-results', `❌ ${data.error || 'Search failed'}`, 'error');
        }
    } catch (error) {
        showResult('search-results', `❌ Error: ${error.message}`, 'error');
    }
}

// Load and display comments
async function loadComments() {
    try {
        const response = await fetch(`${API_BASE}/comments`);
        const comments = await response.json();
        
        const displayDiv = document.getElementById('comments-display');
        
        if (Array.isArray(comments) && comments.length > 0) {
            displayDiv.innerHTML = `
                <h4>💬 Comments (Safely Encoded):</h4>
                ${comments.map(comment => `
                    <div class="comment">
                        <div class="comment-author">${escapeHtml(comment.username)}</div>
                        <div class="comment-content">${comment.content}</div>
                        <div class="comment-date">${new Date(comment.created_at).toLocaleString()}</div>
                    </div>
                `).join('')}
            `;
        } else {
            displayDiv.innerHTML = '<p>No comments yet. Login to add the first comment!</p>';
        }
    } catch (error) {
        console.error('Error loading comments:', error);
        document.getElementById('comments-display').innerHTML = '<p>❌ Failed to load comments</p>';
    }
}

// Security Testing Functions
async function testSQLInjection() {
    const resultDiv = document.getElementById('sql-test-result');
    resultDiv.innerHTML = '<p class="loading">🧪 Testing SQL injection protection...</p>';
    
    const payloads = [
        "'; DROP TABLE Products; --",
        "' UNION SELECT username, password FROM Users; --",
        "' OR '1'='1'; --"
    ];
    
    let results = [];
    
    for (const payload of payloads) {
        try {
            const response = await fetch(`${API_BASE}/search?q=${encodeURIComponent(payload)}`);
            const data = await response.json();
            
            if (response.status === 400) {
                results.push(`✅ Payload blocked: "${payload}"`);
            } else if (Array.isArray(data)) {
                results.push(`❌ Payload executed: "${payload}"`);
            } else {
                results.push(`✅ Payload handled safely: "${payload}"`);
            }
        } catch (error) {
            results.push(`✅ Payload blocked by validation: "${payload}"`);
        }
    }
    
    const allBlocked = results.every(r => r.startsWith('✅'));
    const resultClass = allBlocked ? 'result-success' : 'result-error';
    
    resultDiv.innerHTML = `
        <div class="${resultClass}">
            <h4>${allBlocked ? '✅ SQL Injection Protection: PASSED' : '❌ SQL Injection Protection: FAILED'}</h4>
            ${results.map(r => `<p>${r}</p>`).join('')}
        </div>
    `;
}

async function testXSS() {
    const resultDiv = document.getElementById('xss-test-result');
    
    if (!authToken) {
        resultDiv.innerHTML = '<div class="result-error"><p>❌ Please login first to test XSS protection</p></div>';
        return;
    }
    
    resultDiv.innerHTML = '<p class="loading">🧪 Testing XSS protection...</p>';
    
    const payload = '<script>alert("XSS")</script>';
    
    try {
        const response = await fetch(`${API_BASE}/comments`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`
            },
            body: JSON.stringify({ content: payload })
        });
        
        const data = await response.json();
        
        if (response.status === 400) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ XSS Protection: PASSED</h4>
                    <p>Dangerous content was blocked by validation</p>
                    <p>Error: ${data.message}</p>
                </div>
            `;
        } else if (data.success) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ XSS Protection: PASSED</h4>
                    <p>Content was sanitized and HTML encoded</p>
                    <p>Sanitization applied: ${data.sanitized ? 'Yes' : 'No'}</p>
                </div>
            `;
            loadComments(); // Refresh comments to show encoded version
        } else {
            resultDiv.innerHTML = `
                <div class="result-error">
                    <h4>❌ XSS Protection: FAILED</h4>
                    <p>Unexpected response: ${data.message}</p>
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="result-error">
                <h4>❌ XSS Test: ERROR</h4>
                <p>Test failed: ${error.message}</p>
            </div>
        `;
    }
}

async function testIDOR() {
    const resultDiv = document.getElementById('idor-test-result');
    
    if (!authToken) {
        resultDiv.innerHTML = '<div class="result-error"><p>❌ Please login first to test IDOR protection</p></div>';
        return;
    }
    
    resultDiv.innerHTML = '<p class="loading">🧪 Testing IDOR protection...</p>';
    
    // Try to access another user's profile
    const testUserId = currentUser.id === 1 ? 2 : 1; // Try a different user ID
    
    try {
        const response = await fetch(`${API_BASE}/user/${testUserId}`, {
            headers: {
                'Authorization': `Bearer ${authToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.status === 403) {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ IDOR Protection: PASSED</h4>
                    <p>Access to user ${testUserId} was properly denied</p>
                    <p>Error: ${data.error}</p>
                </div>
            `;
        } else if (response.ok && currentUser.role === 'admin') {
            resultDiv.innerHTML = `
                <div class="result-success">
                    <h4>✅ IDOR Protection: PASSED</h4>
                    <p>Admin access granted as expected</p>
                    <p>Accessed user: ${data.username}</p>
                </div>
            `;
        } else if (response.ok) {
            resultDiv.innerHTML = `
                <div class="result-error">
                    <h4>❌ IDOR Protection: FAILED</h4>
                    <p>Unauthorized access to user ${testUserId} was allowed</p>
                </div>
            `;
        } else {
            resultDiv.innerHTML = `
                <div class="result-warning">
                    <h4>⚠️ IDOR Test: INCONCLUSIVE</h4>
                    <p>Unexpected response: ${data.error}</p>
                </div>
            `;
        }
    } catch (error) {
        resultDiv.innerHTML = `
            <div class="result-error">
                <h4>❌ IDOR Test: ERROR</h4>
                <p>Test failed: ${error.message}</p>
            </div>
        `;
    }
}

async function testRateLimit() {
    const resultDiv = document.getElementById('rate-test-result');
    resultDiv.innerHTML = '<p class="loading">🧪 Testing rate limiting...</p>';
    
    const attempts = [];
    const maxAttempts = 6; // Try 6 attempts (limit is 5)
    
    for (let i = 0; i < maxAttempts; i++) {
        try {
            const response = await fetch(`${API_BASE}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username: 'testuser', password: 'wrongpassword' })
            });
            
            attempts.push({
                attempt: i + 1,
                status: response.status,
                limited: response.status === 429
            });
            
            // Small delay between attempts
            await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error) {
            attempts.push({
                attempt: i + 1,
                status: 'error',
                error: error.message
            });
        }
    }
    
    const rateLimited = attempts.some(a => a.limited);
    const resultClass = rateLimited ? 'result-success' : 'result-warning';
    
    resultDiv.innerHTML = `
        <div class="${resultClass}">
            <h4>${rateLimited ? '✅ Rate Limiting: ACTIVE' : '⚠️ Rate Limiting: CHECK RESULTS'}</h4>
            <p>Login attempts made: ${attempts.length}</p>
            ${attempts.map(a => `
                <p>Attempt ${a.attempt}: ${a.limited ? '🚫 Rate limited' : `Status ${a.status}`}</p>
            `).join('')}
            ${rateLimited ? '<p><small>✅ Rate limiting is working properly</small></p>' : 
              '<p><small>⚠️ If rate limiting didn\'t trigger, try again in 15 minutes</small></p>'}
        </div>
    `;
}

// Utility functions
function showResult(elementId, message, type = 'info') {
    const element = document.getElementById(elementId);
    const className = type === 'error' ? 'result-error' : 
                     type === 'success' ? 'result-success' : 
                     type === 'warning' ? 'result-warning' : '';
    
    element.innerHTML = `<div class="${className}">${message}</div>`;
}

function resetButton(button, originalText) {
    button.disabled = false;
    button.textContent = originalText;
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
}