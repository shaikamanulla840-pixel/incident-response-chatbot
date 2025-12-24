from flask import Flask, request, jsonify
from flask_cors import CORS
from chatbot.core import Chatbot

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

chatbot = Chatbot() # Initialize the chatbot

@app.route('/api/playbooks')
def get_playbooks():
    return jsonify(chatbot.playbooks)

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message')
    if not user_message:
        return jsonify({"error": "No message provided"}), 400

    bot_response = chatbot.get_response(user_message)

    return jsonify({"response": bot_response})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
