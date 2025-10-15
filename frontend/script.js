const API_BASE = 'http://localhost:8000/api';
let currentUser = null;
let authToken = null;
let currentQuoteToComplete = null;

// Check network access on startup
async function checkNetworkAccess() {
    try {
        const response = await fetch(`${API_BASE}/network-status`);
        const status = await response.json();
        
        if (response.ok) {
            console.log('Network status:', status);
            return true;
        } else {
            throw new Error('Network access check failed');
        }
    } catch (error) {
        console.error('Network access check error:', error);
        showNetworkErrorMessage();
        return false;
    }
}

function showNetworkErrorMessage() {
    const errorHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        ">
            <div style="
                background: white;
                padding: 2rem;
                border-radius: 12px;
                text-align: center;
                max-width: 500px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            ">
                <div style="font-size: 3rem; color: #e74c3c; margin-bottom: 1rem;">🚫</div>
                <h2 style="color: #2c3e50; margin-bottom: 1rem;">Network Access Required</h2>
                <p style="line-height: 1.6; margin-bottom: 1rem;">
                    This application requires access to the Protolabs network or VPN connection.
                </p>
                <p style="color: #666; font-size: 0.9rem; font-style: italic;">
                    Please ensure you are connected to the Protolabs network and refresh this page.
                </p>
                <button onclick="window.location.reload()" style="
                    background: #3498db;
                    color: white;
                    border: none;
                    padding: 0.8rem 1.5rem;
                    border-radius: 6px;
                    cursor: pointer;
                    margin-top: 1rem;
                    font-size: 1rem;
                ">
                    Retry Connection
                </button>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('afterbegin', errorHTML);
}

// Authentication functions
function getAuthHeaders() {
    return authToken ? { 'Authorization': `Bearer ${authToken}` } : {};
}

async function login(username, password) {
    try {
        const response = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        if (response.ok) {
            const data = await response.json();
            authToken = data.access_token;
            currentUser = data.user;
            localStorage.setItem('authToken', authToken);
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            showMainApp();
            return true;
        } else {
            const error = await response.json();
            
            // Handle network access denied specifically
            if (error.error_code === 'NETWORK_ACCESS_DENIED') {
                showNetworkAccessDeniedDialog(error);
                return false;
            }
            
            throw new Error(error.detail);
        }
    } catch (error) {
        console.error('Login error:', error);
        
        // Check if it's a network access error
        if (error.message.includes('Network access denied') || error.message.includes('NETWORK_ACCESS_DENIED')) {
            showNetworkAccessDeniedDialog();
            return false;
        }
        
        throw error;
    }
}

function showNetworkAccessDeniedDialog(errorData = null) {
    const clientIP = errorData?.client_ip || 'Unknown';
    
    const dialogHTML = `
        <div id="network-access-denied" style="
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        ">
            <div style="
                background: white;
                padding: 2rem;
                border-radius: 12px;
                text-align: center;
                max-width: 500px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.3);
            ">
                <div style="font-size: 3rem; color: #e74c3c; margin-bottom: 1rem;">🚫</div>
                <h2 style="color: #2c3e50; margin-bottom: 1rem;">Network Access Denied</h2>
                <p style="line-height: 1.6; margin-bottom: 1rem;">
                    This application is only accessible from the Protolabs corporate network or VPN connection.
                </p>
                <div style="
                    background: #f8f9fa;
                    padding: 1rem;
                    border-radius: 6px;
                    margin: 1rem 0;
                    font-family: monospace;
                    font-size: 0.9rem;
                ">
                    Your IP: ${clientIP}<br>
                    Time: ${new Date().toLocaleString()}
                </div>
                <p style="color: #666; font-size: 0.9rem; font-style: italic; margin-bottom: 1.5rem;">
                    Please ensure you are connected to the Protolabs network or VPN, then try again.
                    If the problem persists, contact IT support.
                </p>
                <div>
                    <button onclick="window.location.reload()" style="
                        background: #3498db;
                        color: white;
                        border: none;
                        padding: 0.8rem 1.5rem;
                        border-radius: 6px;
                        cursor: pointer;
                        margin-right: 1rem;
                        font-size: 1rem;
                    ">
                        Retry Connection
                    </button>
                    <button onclick="document.getElementById('network-access-denied').remove()" style="
                        background: #95a5a6;
                        color: white;
                        border: none;
                        padding: 0.8rem 1.5rem;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 1rem;
                    ">
                        Close
                    </button>
                </div>
            </div>
        </div>
    `;
    
    // Remove any existing dialog
    const existing = document.getElementById('network-access-denied');
    if (existing) existing.remove();
    
    document.body.insertAdjacentHTML('afterbegin', dialogHTML);
}

async function register(email, password, role) {
    try {
        const response = await fetch(`${API_BASE}/auth/self-register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password, role })
        });

        if (response.ok) {
            const data = await response.json();
            const roleDesc = role === 'sales' ? 'Sales' : 'Analyst';
            alert(`Account created successfully! Your username is: ${data.username}. You now have ${roleDesc} access. Please log in to continue.`);
            showLoginForm();
            return true;
        } else {
            const error = await response.json();
            
            // Handle network access denied specifically
            if (error.error_code === 'NETWORK_ACCESS_DENIED') {
                showNetworkAccessDeniedDialog(error);
                return false;
            }
            
            throw new Error(error.detail);
        }
    } catch (error) {
        console.error('Registration error:', error);
        
        // Check if it's a network access error
        if (error.message.includes('Network access denied') || error.message.includes('NETWORK_ACCESS_DENIED')) {
            showNetworkAccessDeniedDialog();
            return false;
        }
        
        throw error;
    }
}

function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    showLoginScreen();
}

function showLoginScreen() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('app').classList.remove('logged-in');
}

function showMainApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app').classList.add('logged-in');
    updateUIForCurrentUser();
    loadDashboardData();
}

function showLoginForm() {
    document.getElementById('login-section').style.display = 'block';
    document.getElementById('register-section').style.display = 'none';
    document.getElementById('auth-title').textContent = 'Hot Quotes Management';
    document.getElementById('login-form').reset();
}

function showRegisterForm() {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('register-section').style.display = 'block';
    document.getElementById('auth-title').textContent = 'Create Account';
    document.getElementById('register-form').reset();
}

function updateUIForCurrentUser() {
    if (!currentUser) return;

    document.getElementById('current-user-name').textContent = currentUser.full_name;
    const roleElement = document.getElementById('current-user-role');
    roleElement.textContent = currentUser.role;
    roleElement.className = `role-badge ${currentUser.role}`;

    updateNavigationForRole();
    showDefaultSectionForRole();
}

function updateNavigationForRole() {
    const nav = document.getElementById('main-nav');
    nav.innerHTML = '';

    const buttons = [];

    // Role-specific navigation
    if (currentUser.role === 'admin') {
        buttons.push(
            { id: 'admin-dashboard', text: 'Dashboard', default: true },
            { id: 'queue', text: 'Quote Queue' },
            { id: 'myclaims', text: 'My Claims' },
            { id: 'allquotes', text: 'All Quotes' },
            { id: 'completed', text: 'Completed' },
            { id: 'submit', text: 'Submit Quote' },
            { id: 'users', text: 'User Management' }
        );
    } else if (currentUser.role === 'sales') {
        buttons.push(
            { id: 'sales-dashboard', text: 'Dashboard', default: true },
            { id: 'submit', text: 'Submit Quote' },
            { id: 'allquotes', text: 'My Quotes' },
            { id: 'completed', text: 'Completed' }
        );
    } else if (currentUser.role === 'analyst') {
        buttons.push(
            { id: 'analyst-dashboard', text: 'Dashboard', default: true },
            { id: 'queue', text: 'Available Queue' },
            { id: 'myclaims', text: 'My Claims' },
            { id: 'completed', text: 'My Completed' }
        );
    }

    buttons.forEach(button => {
        const btn = document.createElement('button');
        btn.textContent = button.text;
        btn.setAttribute('data-section', button.id);
        btn.onclick = () => showSection(button.id, btn);
        if (button.default) {
            btn.classList.add('active');
        }
        nav.appendChild(btn);
    });
}

function showSection(sectionName, clickedButton = null) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Update nav buttons
    document.querySelectorAll('#main-nav button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected section
    document.getElementById(sectionName).classList.add('active');
    
    // Update active nav button
    if (clickedButton) {
        clickedButton.classList.add('active');
    } else {
        // Find the button for this section
        const targetButton = document.querySelector(`#main-nav button[data-section="${sectionName}"]`);
        if (targetButton) {
            targetButton.classList.add('active');
        }
    }
    
    // Load data when section is shown
    switch(sectionName) {
        case 'admin-dashboard':
        case 'sales-dashboard':
        case 'analyst-dashboard':
            loadDashboardData();
            break;
        case 'queue':
            loadQueue();
            break;
        case 'myclaims':
            loadMyClaims();
            break;
        case 'allquotes':
            loadAllQuotes();
            break;
        case 'completed':
            loadCompleted();
            break;
        case 'users':
            loadUsers();
            break;
    }
}

function showDefaultSectionForRole() {
    const defaultSections = {
        'admin': 'admin-dashboard',
        'sales': 'sales-dashboard',
        'analyst': 'analyst-dashboard'
    };
    
    const defaultSection = defaultSections[currentUser.role];
    if (defaultSection) {
        showSection(defaultSection);
    }
}

// Enhanced error handling for API calls
async function makeAPICall(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                ...getAuthHeaders()
            }
        });

        if (response.status === 403) {
            const error = await response.json();
            if (error.error_code === 'NETWORK_ACCESS_DENIED') {
                showNetworkAccessDeniedDialog(error);
                throw new Error('Network access denied');
            }
        }

        return response;
    } catch (error) {
        if (error.message === 'Network access denied') {
            throw error;
        }
        
        // Handle network connectivity issues
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            console.error('Network connectivity issue:', error);
            alert('Network connectivity issue. Please check your connection to the Protolabs network.');
        }
        
        throw error;
    }
}

// Dashboard data loading
async function loadDashboardData() {
    try {
        const response = await makeAPICall(`${API_BASE}/analytics/summary`);
        const data = await response.json();
        
        // Update common stats
        const elements = {
            'available-count': data.available_quotes,
            'claimed-count': data.claimed_quotes,
            'completed-count': data.completed_quotes,
            'sales-available-count': data.available_quotes,
            'sales-claimed-count': data.claimed_quotes,
            'sales-completed-count': data.completed_quotes,
            'sales-total-count': data.total_quotes,
            'analyst-available-count': data.available_quotes,
            'analyst-claims-count': data.my_claims || 0,
            'analyst-completed-count': data.completed_quotes
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        });

        // Load users count for admin
        if (currentUser.role === 'admin') {
            loadUsersCount();
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading dashboard data:', error);
        }
    }
}

async function loadUsersCount() {
    try {
        const response = await makeAPICall(`${API_BASE}/users/`);
        const users = await response.json();
        const element = document.getElementById('total-users');
        if (element) element.textContent = users.length;
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading users count:', error);
        }
    }
}

// Quote management functions
async function loadQueue() {
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/available`);
        const quotes = await response.json();
        
        const container = document.getElementById('quotes-list');
        container.innerHTML = '';
        
        if (quotes.length === 0) {
            container.innerHTML = '<div class="no-quotes">No quotes available in queue</div>';
            return;
        }
        
        quotes.forEach(quote => {
            const element = createQuoteElement(quote, 'available');
            container.appendChild(element);
        });
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading queue:', error);
        }
    }
}

async function loadMyClaims() {
    if (!currentUser) return;
    
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/claimed-by/${currentUser.username}`);
        const quotes = await response.json();
        
        const container = document.getElementById('my-claims-list');
        container.innerHTML = '';
        
        if (quotes.length === 0) {
            container.innerHTML = '<div class="no-quotes">No claimed quotes</div>';
            return;
        }
        
        quotes.forEach(quote => {
            const element = createQuoteElement(quote, 'claimed');
            container.appendChild(element);
        });
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading my claims:', error);
        }
    }
}

async function loadAllQuotes() {
    try {
        const statusFilter = document.getElementById('status-filter');
        const status = statusFilter ? statusFilter.value : '';
        
        const url = status ? `${API_BASE}/quotes/?status=${status}` : `${API_BASE}/quotes/`;
        const response = await makeAPICall(url);
        const quotes = await response.json();
        
        const container = document.getElementById('all-quotes-list');
        container.innerHTML = '';
        
        if (quotes.length === 0) {
            container.innerHTML = '<div class="no-quotes">No quotes found</div>';
            return;
        }
        
        quotes.forEach(quote => {
            const context = quote.status === 'claimed' && quote.claimed_by === currentUser.username ? 'claimed' : quote.status;
            const element = createQuoteElement(quote, context);
            container.appendChild(element);
        });
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading all quotes:', error);
        }
    }
}

async function loadCompleted() {
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/completed`);
        const quotes = await response.json();
        
        const container = document.getElementById('completed-list');
        container.innerHTML = '';
        
        if (quotes.length === 0) {
            container.innerHTML = '<div class="no-quotes">No completed quotes</div>';
            return;
        }
        
        quotes.forEach(quote => {
            const element = createQuoteElement(quote, 'completed');
            container.appendChild(element);
        });
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading completed quotes:', error);
        }
    }
}

function createQuoteElement(quote, context) {
    const div = document.createElement('div');
    div.className = `quote-card ${quote.priority}-priority ${context}`;
    
    let actionsHTML = '';
    let metaHTML = '';
    let reasonDisplay = quote.reason_for_hot;
    if (quote.reason_for_hot === 'other' && quote.reason_other_text) {
        reasonDisplay += `: ${quote.reason_other_text}`;
    }
    
    // File display
    let fileHTML = '';
    if (quote.original_filename) {
        fileHTML = `<p><strong>File:</strong> <a href="${API_BASE}/quotes/${quote.id}/download" download="${quote.original_filename}">${quote.original_filename}</a></p>`;
    }
    
    // CC emails display
    let ccEmailsHTML = '';
    if (quote.additional_cc_emails) {
        try {
            const ccEmails = JSON.parse(quote.additional_cc_emails);
            if (ccEmails && ccEmails.length > 0) {
                ccEmailsHTML = `<p><strong>CC Emails:</strong> ${ccEmails.join(', ')}</p>`;
            }
        } catch (e) {
            // Handle parsing error gracefully
        }
    }
    
    if (context === 'available' && (currentUser.role === 'analyst' || currentUser.role === 'admin')) {
        actionsHTML = `<button onclick="claimQuote(${quote.id})">Claim Quote</button>`;
    } else if (context === 'claimed') {
        const canManage = currentUser.role === 'admin' || quote.claimed_by === currentUser.username;
        if (canManage) {
            actionsHTML = `
                <button onclick="openCompletionModal(${quote.id})" class="complete-btn">Complete</button>
                <button onclick="unclaimQuote(${quote.id})" class="unclaim-btn">Unclaim</button>
            `;
        }
        metaHTML = `
            <div class="quote-meta">
                <div><strong>Claimed:</strong> ${new Date(quote.claimed_at).toLocaleString()}</div>
                <div><strong>Claimed by:</strong> ${quote.claimed_by}</div>
            </div>
        `;
    } else if (context === 'completed') {
        metaHTML = `
            <div class="quote-meta">
                <div><strong>Submitted by:</strong> ${quote.submitted_by}</div>
                <div><strong>Completed by:</strong> ${quote.claimed_by}</div>
                <div><strong>Completed:</strong> ${new Date(quote.completed_at).toLocaleString()}</div>
            </div>
        `;
        if (quote.notes) {
            metaHTML += `<div class="completion-notes"><strong>Notes:</strong> ${quote.notes}</div>`;
        }
    }
    
    // Add submission info for non-sales users or admin
    let submissionInfo = '';
    if (currentUser.role !== 'sales' || currentUser.role === 'admin') {
        submissionInfo = `<p><strong>Submitted by:</strong> ${quote.submitted_by}</p>`;
    }
    
    div.innerHTML = `
        <div class="quote-header">
            <h3>${quote.quote_number}</h3>
            <span class="priority-badge ${quote.priority}">${quote.priority.toUpperCase()}</span>
        </div>
        <p><strong>Reason for Hot:</strong> ${reasonDisplay}</p>
        <p><strong>Additional Info:</strong> ${quote.additional_info}</p>
        <p><strong>Special Process:</strong> ${quote.special_process}</p>
        ${quote.subject_line ? `<p><strong>Subject:</strong> ${quote.subject_line}</p>` : ''}
        ${ccEmailsHTML}
        ${fileHTML}
        ${submissionInfo}
        <p><strong>Submitted:</strong> ${new Date(quote.created_at).toLocaleString()}</p>
        ${metaHTML}
        <div class="quote-actions">
            ${actionsHTML}
        </div>
    `;
    
    return div;
}

// Quote actions
async function claimQuote(quoteId) {
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/${quoteId}/claim`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Quote claimed successfully!');
            loadQueue();
            loadDashboardData();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error claiming quote:', error);
            alert('Error claiming quote');
        }
    }
}

async function unclaimQuote(quoteId) {
    if (!confirm('Are you sure you want to unclaim this quote? It will go back to the available queue.')) {
        return;
    }
    
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/${quoteId}/unclaim`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Quote unclaimed successfully!');
            loadMyClaims();
            loadDashboardData();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error unclaiming quote:', error);
            alert('Error unclaiming quote');
        }
    }
}

function openCompletionModal(quoteId) {
    currentQuoteToComplete = quoteId;
    document.getElementById('completion-modal').style.display = 'flex';
    document.getElementById('completion-notes').value = '';
}

function closeModal() {
    document.getElementById('completion-modal').style.display = 'none';
    currentQuoteToComplete = null;
}

async function submitCompletion() {
    if (!currentQuoteToComplete) return;
    
    const notes = document.getElementById('completion-notes').value.trim();
    
    try {
        const response = await makeAPICall(`${API_BASE}/quotes/${currentQuoteToComplete}/complete?completion_notes=${encodeURIComponent(notes)}`, {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Quote completed successfully!');
            closeModal();
            loadMyClaims();
            loadDashboardData();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error completing quote:', error);
            alert('Error completing quote');
        }
    }
}

// Form helper functions
function toggleOtherReason() {
    const reasonSelect = document.getElementById('reason-for-hot');
    const otherGroup = document.getElementById('other-reason-group');
    const otherInput = document.getElementById('reason-other-text');
    
    if (reasonSelect.value === 'other') {
        otherGroup.style.display = 'block';
        otherInput.required = true;
    } else {
        otherGroup.style.display = 'none';
        otherInput.required = false;
        otherInput.value = '';
    }
}

function addCCEmail() {
    const container = document.getElementById('cc-emails-container');
    const emailInput = document.createElement('div');
    emailInput.className = 'cc-email-input';
    emailInput.innerHTML = `
        <input type="email" class="cc-email" placeholder="Enter email address">
        <button type="button" onclick="removeCCEmail(this)" class="remove-cc-btn">Remove</button>
    `;
    container.appendChild(emailInput);
}

function removeCCEmail(button) {
    const container = document.getElementById('cc-emails-container');
    if (container.children.length > 1) {
        button.parentElement.remove();
    }
}

function collectCCEmails() {
    const ccInputs = document.querySelectorAll('.cc-email');
    const emails = [];
    ccInputs.forEach(input => {
        if (input.value.trim()) {
            emails.push(input.value.trim());
        }
    });
    return emails;
}

// User management functions
async function loadUsers() {
    if (currentUser.role !== 'admin') return;
    
    try {
        const response = await makeAPICall(`${API_BASE}/users/`);
        const users = await response.json();
        
        const container = document.getElementById('users-list-container');
        
        if (users.length === 0) {
            container.innerHTML = '<div class="no-quotes">No users found</div>';
            return;
        }
        
        const table = document.createElement('table');
        table.className = 'users-table';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>Username</th>
                    <th>Full Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                ${users.map(user => {
                    const isCurrentUser = user.id === currentUser.id;
                    const roleOptions = ['admin', 'sales', 'analyst']
                        .map(role => `<option value="${role}" ${user.role === role ? 'selected' : ''}>${role}</option>`)
                        .join('');
                    
                    return `
                        <tr>
                            <td>${user.username}</td>
                            <td>${user.full_name}</td>
                            <td>${user.email}</td>
                            <td>
                                ${isCurrentUser ? 
                                    `<span class="role-badge ${user.role}">${user.role}</span>` : 
                                    `<select class="role-selector" onchange="updateUserRole(${user.id}, this.value)">
                                        ${roleOptions}
                                    </select>`
                                }
                            </td>
                            <td>${user.is_active ? 'Active' : 'Inactive'}</td>
                            <td>${new Date(user.created_at).toLocaleDateString()}</td>
                            <td class="user-actions">
                                ${isCurrentUser ? 
                                    '<span class="current-user-label">Current User</span>' : 
                                    `<button onclick="deleteUser(${user.id}, '${user.username}')" class="delete-user-btn">Delete</button>`
                                }
                            </td>
                        </tr>
                    `;
                }).join('')}
            </tbody>
        `;
        
        container.innerHTML = '';
        container.appendChild(table);
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error loading users:', error);
        }
    }
}

async function updateUserRole(userId, newRole) {
    if (!confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
        loadUsers(); // Reload to reset the dropdown
        return;
    }
    
    try {
        const response = await makeAPICall(`${API_BASE}/users/${userId}/role`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ role: newRole })
        });
        
        if (response.ok) {
            alert('User role updated successfully!');
            loadUsers();
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
            loadUsers(); // Reload to reset the dropdown
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error updating user role:', error);
            alert('Error updating user role');
        }
        loadUsers(); // Reload to reset the dropdown
    }
}

async function deleteUser(userId, username) {
    if (!confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
        return;
    }
    
    // Second confirmation for safety
    if (!confirm('This will permanently delete the user account. Are you absolutely sure?')) {
        return;
    }
    
    try {
        const response = await makeAPICall(`${API_BASE}/users/${userId}`, {
            method: 'DELETE'
        });
        
        if (response.ok) {
            alert('User deleted successfully!');
            loadUsers();
            loadDashboardData(); // Update user count
        } else {
            const error = await response.json();
            alert(`Error: ${error.detail}`);
        }
    } catch (error) {
        if (error.message !== 'Network access denied') {
            console.error('Error deleting user:', error);
            alert('Error deleting user');
        }
    }
}

function showAddUserModal() {
    document.getElementById('add-user-modal').style.display = 'flex';
}

function closeAddUserModal() {
    document.getElementById('add-user-modal').style.display = 'none';
    document.getElementById('add-user-form').reset();
}

// Refresh functions
function refreshQueue() { loadQueue(); }
function refreshMyClaims() { loadMyClaims(); }
function refreshAllQuotes() { loadAllQuotes(); }
function refreshCompleted() { loadCompleted(); }

// Event listeners
document.addEventListener('DOMContentLoaded', async () => {
    // Check network access first
    const networkAccessible = await checkNetworkAccess();
    if (!networkAccessible) {
        return; // Stop initialization if network access is denied
    }
    
    // Check for existing login
    const savedToken = localStorage.getItem('authToken');
    const savedUser = localStorage.getItem('currentUser');
    
    if (savedToken && savedUser) {
        authToken = savedToken;
        currentUser = JSON.parse(savedUser);
        showMainApp();
    } else {
        showLoginScreen();
    }
    
    // Show/Hide form toggles
    document.getElementById('show-register').addEventListener('click', (e) => {
        e.preventDefault();
        showRegisterForm();
    });
    
    document.getElementById('show-login').addEventListener('click', (e) => {
        e.preventDefault();
        showLoginForm();
    });
    
    // Login form handler
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const loginBtn = document.getElementById('login-btn');
        const errorDiv = document.getElementById('login-error');
        
        const formData = new FormData(e.target);
        const username = formData.get('username');
        const password = formData.get('password');
        
        loginBtn.textContent = 'Logging in...';
        loginBtn.disabled = true;
        errorDiv.style.display = 'none';
        
        try {
            await login(username, password);
        } catch (error) {
            // Don't show error message if it's network access denied (handled separately)
            if (!error.message.includes('Network access denied')) {
                errorDiv.textContent = error.message;
                errorDiv.style.display = 'block';
            }
        } finally {
            loginBtn.textContent = 'Login';
            loginBtn.disabled = false;
        }
    });
    
    // Registration form handler - UPDATED TO INCLUDE ROLE
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const registerBtn = document.getElementById('register-btn');
        const errorDiv = document.getElementById('login-error');
        
        const formData = new FormData(e.target);
        const email = formData.get('email');
        const password = formData.get('password');
        const role = formData.get('role');
        
        // Client-side validation
        if (!role) {
            errorDiv.textContent = 'Please select an account type';
            errorDiv.style.display = 'block';
            return;
        }
        
        registerBtn.textContent = 'Creating Account...';
        registerBtn.disabled = true;
        errorDiv.style.display = 'none';
        
        try {
            await register(email, password, role);
        } catch (error) {
            // Don't show error message if it's network access denied (handled separately)
            if (!error.message.includes('Network access denied')) {
                errorDiv.textContent = error.message;
                errorDiv.style.display = 'block';
            }
        } finally {
            registerBtn.textContent = 'Create Account';
            registerBtn.disabled = false;
        }
    });
    
    // Quote form handler
    document.getElementById('quote-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        
        // Collect CC emails
        const ccEmails = collectCCEmails();
        formData.append('additional_cc_emails', JSON.stringify(ccEmails));
        
        try {
            const response = await makeAPICall(`${API_BASE}/quotes/`, {
                method: 'POST',
                body: formData
            });
            
            if (response.ok) {
                alert('Quote submitted successfully!');
                e.target.reset();
                // Reset CC emails to single input
                const container = document.getElementById('cc-emails-container');
                container.innerHTML = `
                    <div class="cc-email-input">
                        <input type="email" class="cc-email" placeholder="Enter email address">
                        <button type="button" onclick="removeCCEmail(this)" class="remove-cc-btn">Remove</button>
                    </div>
                `;
                // Hide other reason field
                document.getElementById('other-reason-group').style.display = 'none';
                loadDashboardData();
            } else {
                const error = await response.json();
                alert(`Error: ${error.detail}`);
            }
        } catch (error) {
            if (error.message !== 'Network access denied') {
                console.error('Error submitting quote:', error);
                alert('Error submitting quote');
            }
        }
    });
    
    // Add user form handler
    document.getElementById('add-user-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const userData = {
            username: formData.get('username'),
            email: formData.get('email'),
            full_name: formData.get('full_name'),
            password: formData.get('password'),
            role: formData.get('role')
        };
        
        try {
            const response = await makeAPICall(`${API_BASE}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(userData)
            });
            
            if (response.ok) {
                alert('User created successfully!');
                closeAddUserModal();
                loadUsers();
            } else {
                const error = await response.json();
                alert(`Error: ${error.detail}`);
            }
        } catch (error) {
            if (error.message !== 'Network access denied') {
                console.error('Error creating user:', error);
                alert('Error creating user');
            }
        }
    });
});