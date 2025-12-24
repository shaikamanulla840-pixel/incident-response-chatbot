document.addEventListener('DOMContentLoaded', () => {
    const chatWindow = document.getElementById('chat-window');
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
    const sidebar = document.getElementById('sidebar');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');
    const playbookList = document.getElementById('playbook-list');
    const playbookSearch = document.getElementById('playbook-search');
    const quickResponseButtons = document.querySelectorAll('.qr-button');
    const exportChatButton = document.getElementById('export-chat-button');
    const clearChatButton = document.getElementById('clear-chat-button');
    const incidentSeveritySelector = document.getElementById('incident-severity'); // New selector

    // --- Sidebar Toggle ---
    sidebarToggle.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        sidebarToggle.querySelector('i').classList.toggle('fa-chevron-left');
        sidebarToggle.querySelector('i').classList.toggle('fa-chevron-right');
    });

    // --- Tab Switching ---
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabContents.forEach(content => content.classList.remove('active'));

            button.classList.add('active');
            document.getElementById(`${button.dataset.tab}-tab`).classList.add('active');
        });
    });

    // --- Incident Severity Selector ---
    incidentSeveritySelector.addEventListener('change', (event) => {
        const selectedSeverity = event.target.value;
        console.log('Selected Incident Severity:', selectedSeverity);
        // In a more advanced scenario, this value would be sent to the backend
        // or used to filter displayed information.
    });

    // --- Chat Message Management ---
    function appendMessage(sender, message) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', `${sender}-message`);

        // Simple Markdown parsing for bot messages
        if (sender === 'bot') {
            let htmlMessage = message;
            // Headings (###)
            htmlMessage = htmlMessage.replace(/^### (.*$)/gim, '<h3>$1</h3>');
            // Bold (**text**)
            htmlMessage = htmlMessage.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
            // Lists (1. Item or * Item)
            htmlMessage = htmlMessage.replace(/^\s*(\d+\.\s.*)$/gim, '<li>$1</li>');
            htmlMessage = htmlMessage.replace(/^\s*(\*\s.*)$/gim, '<li>$1</li>');
            if (htmlMessage.includes('<li>')) {
                // Ensure list items are wrapped in ol/ul if not already
                if (!htmlMessage.startsWith('<ol>') && !htmlMessage.startsWith('<ul>')) {
                    htmlMessage = `<ol>${htmlMessage}</ol>`;
                }
            }
            // Code blocks (simple, for now assume single line or pre-formatted)
            htmlMessage = htmlMessage.replace(/`(.*?)`/g, '<code>$1</code>');


            messageElement.innerHTML = htmlMessage;
        } else {
            messageElement.textContent = message;
        }
        
        chatWindow.appendChild(messageElement);
        chatWindow.scrollTop = chatWindow.scrollHeight; // Scroll to bottom
    }

    // --- Send Message Functionality ---
    sendButton.addEventListener('click', sendMessage);
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault(); // Prevent new line
            sendMessage();
        }
    });

    async function sendMessage() {
        const message = userInput.value.trim();
        if (message === '') return;

        appendMessage('user', message);
        userInput.value = '';

        try {
            const response = await fetch('/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: message })
            });

            const data = await response.json();
            if (data.response) {
                appendMessage('bot', data.response);
            } else if (data.error) {
                appendMessage('bot', `Error: ${data.error}`);
            }
        } catch (error) {
            console.error('Error sending message:', error);
            appendMessage('bot', 'Sorry, I am having trouble connecting to the server.');
        }
    }

    // --- Quick Response Actions ---
    quickResponseButtons.forEach(button => {
        button.addEventListener('click', () => {
            const incidentType = button.dataset.incidentType;
            userInput.value = `Tell me about ${incidentType.replace('_', ' ')}`;
            sendMessage();
        });
    });

    // --- Export Chat ---
    exportChatButton.addEventListener('click', () => {
        let chatLog = "Incident Response Chat Log\n\n";
        chatWindow.querySelectorAll('.message').forEach(msg => {
            const sender = msg.classList.contains('user-message') ? 'You' : 'Assistant';
            chatLog += `${sender}: ${msg.textContent}\n\n`;
        });
        const blob = new Blob([chatLog], { type: 'text/plain' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `chat-log-${new Date().toISOString().slice(0, 10)}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        appendMessage('bot', 'Chat log exported successfully!');
    });

    // --- Clear Chat ---
    clearChatButton.addEventListener('click', () => {
        if (confirm('Are you sure you want to clear the chat history? This action cannot be undone.')) {
            chatWindow.innerHTML = '';
            appendMessage('bot', 'Chat history cleared. How can I assist you now?');
        }
    });

    // --- Dynamic Playbook Loading ---
    let availablePlaybooks = []; // To store fetched playbooks

    async function fetchPlaybooks() {
        try {
            const response = await fetch('/api/playbooks');
            const data = await response.json();
            
            // Convert the object of playbooks into an array for easier filtering/rendering
            availablePlaybooks = Object.keys(data).map(key => ({
                key: key,
                ...data[key]
            }));
            renderPlaybooks(availablePlaybooks);
        } catch (error) {
            console.error('Error fetching playbooks:', error);
            appendMessage('bot', 'Sorry, I could not load the playbooks at this moment.');
        }
    }

    function renderPlaybooks(playbooksToRender) {
        playbookList.innerHTML = '';
        if (playbooksToRender.length === 0) {
            playbookList.innerHTML = '<p class="no-results">No playbooks found.</p>';
            return;
        }
        playbooksToRender.forEach(playbook => {
            const playbookCard = document.createElement('div');
            playbookCard.classList.add('playbook-card');
            // Ensure color is a valid CSS color if passed directly, otherwise map to classes
            const severityColorClass = `severity-${playbook.severity.toLowerCase()}`;

            playbookCard.innerHTML = `
                <h5 style="color: ${playbook.color};">${playbook.name}</h5>
                <p>${playbook.description}</p>
                <div class="playbook-card-meta">
                    <span><i class="far fa-clock"></i> ${playbook.time_estimate}</span>
                    <span class="severity-tag ${severityColorClass}">${playbook.severity}</span>
                </div>
            `;
            playbookCard.addEventListener('click', () => {
                // When clicking a playbook, automatically ask the chatbot about it
                userInput.value = `Tell me about ${playbook.name}`;
                sendMessage();
            });
            playbookList.appendChild(playbookCard);
        });
    }

    // Call fetchPlaybooks when the DOM is loaded
    fetchPlaybooks();

    playbookSearch.addEventListener('input', () => {
        const searchTerm = playbookSearch.value.toLowerCase();
        const filteredPlaybooks = availablePlaybooks.filter(playbook => 
            playbook.name.toLowerCase().includes(searchTerm) ||
            playbook.description.toLowerCase().includes(searchTerm) ||
            playbook.key.toLowerCase().includes(searchTerm)
        );
        renderPlaybooks(filteredPlaybooks);
    });

    // --- Initial Bot Message ---
    appendMessage('bot', 'Hello! I am your Incident Response Assistant. How can I assist you today?');

    // Placeholder for Recent Incidents Timeline (dynamic content later)
    const recentIncidentsTimeline = document.getElementById('recent-incidents-timeline');
    const now = new Date();
    const incidents = [
        { description: "Detected unusual login attempt", time: new Date(now.getTime() - 3600000) }, // 1 hour ago
        { description: "Phishing email reported by user", time: new Date(now.getTime() - 7200000) }, // 2 hours ago
        { description: "Server reboot activity", time: new Date(now.getTime() - 86400000) } // 1 day ago
    ];
    incidents.forEach(incident => {
        const li = document.createElement('li');
        li.innerHTML = `${incident.description} <br/><span>${incident.time.toLocaleString()}</span>`;
        recentIncidentsTimeline.appendChild(li);
    });
});