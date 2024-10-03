// static/chatbot.js

// Function to send a message
function sendMessage(event) {
    // Check if the function was called by an Enter key press or a button click
    if (event.type === 'keypress' && event.key !== 'Enter') {
        return;
    }

    const input = document.getElementById('user-input');
    const message = input.value.trim();

    if (message) {
        displayMessage(message, 'user');
        input.value = '';
        getBotResponse(message);
    }
}

// Function to display a message in the chatbox
function displayMessage(message, sender) {
    const chatBox = document.getElementById('chat-box');
    const messageElement = document.createElement('div');
    messageElement.className = `chat-message ${sender}`;
    messageElement.innerText = message;
    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight;
}

// Function to fetch the bot's response
function getBotResponse(message) {
    fetch('/chatbot-response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ message: message }),
    })
    .then(response => response.json())
    .then(data => {
        displayMessage(data.response, 'bot');
    })
    .catch(error => {
        console.error('Error:', error);
        displayMessage('Sorry, there was an error. Please try again later.', 'bot');
    });
}
