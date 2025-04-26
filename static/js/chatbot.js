// Chatbot functionality
document.addEventListener('DOMContentLoaded', function() {
    const chatButton = document.getElementById('chatButton');
    const chatWindow = document.getElementById('chatWindow');
    const closeChat = document.getElementById('closeChat');
    const chatMessages = document.getElementById('chatMessages');
    const messageInput = document.getElementById('messageInput');
    const sendMessage = document.getElementById('sendMessage');

    // Toggle chat window
    chatButton.addEventListener('click', () => {
        chatWindow.classList.add('active');
        messageInput.focus();
    });

    closeChat.addEventListener('click', () => {
        chatWindow.classList.remove('active');
    });

    // Close chat when clicking outside
    document.addEventListener('click', (e) => {
        if (!chatWindow.contains(e.target) && !chatButton.contains(e.target)) {
            chatWindow.classList.remove('active');
        }
    });

    // Prevent chat from closing when clicking inside
    chatWindow.addEventListener('click', (e) => {
        e.stopPropagation();
    });

    // Send message function
    function sendUserMessage() {
        const message = messageInput.value.trim();
        if (message) {
            // Add user message to chat
            addMessage(message, 'user');
            messageInput.value = '';

            // Show typing indicator
            showTypingIndicator();

            // Send message to backend
            fetch('/chatbot', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message })
            })
            .then(response => response.json())
            .then(data => {
                // Remove typing indicator
                removeTypingIndicator();
                
                // Add bot response to chat
                if (data.error) {
                    addMessage('Sorry, I encountered an error. Please try again.', 'bot');
                } else {
                    addMessage(data.response, 'bot');
                }
            })
            .catch(error => {
                removeTypingIndicator();
                addMessage('Sorry, I encountered an error. Please try again.', 'bot');
                console.error('Error:', error);
            });
        }
    }

    // Send message on button click
    sendMessage.addEventListener('click', sendUserMessage);

    // Send message on Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendUserMessage();
        }
    });

    // Add message to chat with animation
    function addMessage(text, sender) {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', `${sender}-message`);
        messageDiv.style.opacity = '0';
        messageDiv.style.transform = 'translateY(10px)';
        messageDiv.innerHTML = text;
        chatMessages.appendChild(messageDiv);
        
        // Trigger animation
        setTimeout(() => {
            messageDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            messageDiv.style.opacity = '1';
            messageDiv.style.transform = 'translateY(0)';
        }, 10);
        
        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Show typing indicator with animation
    function showTypingIndicator() {
        const typingDiv = document.createElement('div');
        typingDiv.classList.add('typing-indicator');
        typingDiv.id = 'typingIndicator';
        typingDiv.style.opacity = '0';
        typingDiv.style.transform = 'translateY(10px)';
        
        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('div');
            dot.classList.add('typing-dot');
            typingDiv.appendChild(dot);
        }
        
        chatMessages.appendChild(typingDiv);
        
        // Trigger animation
        setTimeout(() => {
            typingDiv.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            typingDiv.style.opacity = '1';
            typingDiv.style.transform = 'translateY(0)';
        }, 10);
        
        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    // Remove typing indicator with animation
    function removeTypingIndicator() {
        const typingIndicator = document.getElementById('typingIndicator');
        if (typingIndicator) {
            typingIndicator.style.opacity = '0';
            typingIndicator.style.transform = 'translateY(-10px)';
            
            setTimeout(() => {
                typingIndicator.remove();
            }, 300);
        }
    }

    // Add initial greeting if no messages exist
    if (chatMessages.children.length === 0) {
        addMessage('Hello! I\'m Careology, your car dealership assistant. How can I help you find the perfect car today?', 'bot');
    }
});