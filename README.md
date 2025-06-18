# AI Chatbot

A simple AI-powered chatbot built with Flask and OpenAI.

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory and add your OpenAI API key:
```
OPENAI_API_KEY=your_api_key_here
```

4. Run the application:
```bash
python app.py
```

5. Open your browser and navigate to `http://localhost:5000`

## Features

- Real-time chat interface
- Powered by OpenAI's GPT model
- Clean and responsive design
- Message history display
- Comprehensive security features
- Rate limiting and input validation

## Security Features

- Rate limiting: 10/min, 20/hour, 30/day
- Input sanitization and validation
- XSS and SQL injection protection
- Request tracking and logging
- Security headers and CORS protection

## Deployment

Last deployment: 2025-01-17 