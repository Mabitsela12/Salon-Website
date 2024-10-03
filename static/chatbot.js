// Function to send user message to the server
function sendMessage(event) {
    if (event.type === 'keypress' && event.keyCode !== 13) {
        return;
    }

    let userMessage = document.getElementById('user-input').value.trim();
    if (!userMessage) return;

    addMessageToChat('user', userMessage);

    fetch('/chatbot-response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ message: userMessage })
    })
    .then(response => response.json())
    .then(data => {
        let botResponse = data.response;
        addMessageToChat('bot', botResponse);
    })
    .catch(error => console.error('Error:', error));

    document.getElementById('user-input').value = '';
}

// Function to add messages to chat interface
function addMessageToChat(sender, message) {
    let chatBox = document.getElementById('chat-box');
    let messageElement = document.createElement('div');
    messageElement.classList.add('chat-message', sender);
    messageElement.innerText = message;
    chatBox.appendChild(messageElement);
    chatBox.scrollTop = chatBox.scrollHeight;
}

document.getElementById('user-input').addEventListener('keypress', sendMessage);
document.querySelector('button').addEventListener('click', sendMessage);
