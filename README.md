# Incident Response Assistant Chatbot

This project is a web-based chatbot designed to assist SOC analysts, IT teams, and security engineers during cybersecurity incidents. It provides step-by-step guidance, structured playbooks, and best practices to help users identify, analyze, contain, eradicate, and recover from security incidents.

## Features

- **Interactive Chat Interface**: A user-friendly web interface for interacting with the chatbot.
- **Incident Response Playbooks**: Provides detailed playbooks for various security incidents like ransomware attacks, phishing emails, data breaches, and more.
- **Step-by-Step Guidance**: Offers clear and actionable steps for different stages of incident response (Identification, Containment, Eradication, Recovery, Lessons Learned).
- **Dynamic Playbook Library**: Users can browse and search for playbooks in the application.
- **Export Chat**: Ability to export the chat log for documentation and analysis.

## Tech Stack

- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS, JavaScript
- **Core Logic**: Python

## Setup and Installation

1.  **Clone the repository**:
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **Create a virtual environment** (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install the dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the application**:
    ```bash
    python app.py
    ```

5.  Open your web browser and navigate to `http://localhost:5000`.

## Usage

Once the application is running, you can interact with the chatbot by typing messages in the input field. You can ask for guidance on specific incident types (e.g., "tell me about ransomware attack") or for specific stages of an incident (e.g., "containment for phishing email").

The sidebar provides a library of available playbooks and allows you to export the chat history.

## Project Structure

```
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── chatbot/
│   ├── __init__.py
│   └── core.py           # Core chatbot logic and playbooks
├── static/
│   ├── script.js         # Frontend JavaScript
│   └── style.css         # Stylesheet
├── templates/
│   └── index.html        # HTML template for the chat interface
└── README.md             # This file
```
