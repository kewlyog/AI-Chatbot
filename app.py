from flask import Flask, render_template, request, jsonify
from openai import OpenAI
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import re

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

client = OpenAI()

def validate_message(message):
    """Validate the user message for security and content."""
    if not message or not isinstance(message, str):
        return False, "Invalid message format"
    
    # Check message length (max 500 characters)
    if len(message) > 500:
        return False, "Message too long (max 500 characters)"
    
    # Check for potentially harmful content
    harmful_patterns = [
        r'(?i)(password|api[_-]?key|token|secret)',
        r'(?i)(drop|delete|update|insert)\s+table',
        r'(?i)(exec|eval|system|shell)',
        r'(?i)(<script|javascript:)',
    ]
    
    for pattern in harmful_patterns:
        if re.search(pattern, message):
            return False, "Message contains potentially harmful content"
    
    return True, None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@limiter.limit("10 per minute")  # Limit to 10 requests per minute per IP
def chat():
    try:
        data = request.json
        user_message = data.get('message', '')
        
        # Validate the message
        is_valid, error_message = validate_message(user_message)
        if not is_valid:
            return jsonify({
                'error': error_message
            }), 400
        
        # Get response from OpenAI
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful and friendly AI assistant."},
                {"role": "user", "content": user_message}
            ],
            max_tokens=150,
            temperature=0.7  # Add some randomness to responses
        )
        
        ai_response = response.choices[0].message.content
        
        return jsonify({
            'response': ai_response
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

# Error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded. Please try again later.'
    }), 429

if __name__ == '__main__':
    app.run(debug=True) 