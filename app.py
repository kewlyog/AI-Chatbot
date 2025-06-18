from flask import Flask, render_template, request, jsonify, session
from openai import OpenAI
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_talisman import Talisman
from flask_seasurf import SeaSurf
import re
import logging
from datetime import datetime
from security_config import SecurityConfig

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', os.urandom(24))

# Security headers and CSRF protection
Talisman(app, 
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data: https:",
        'font-src': "'self'",
        'connect-src': "'self'"
    },
    force_https=False  # Set to True in production
)

# CSRF protection
csrf = SeaSurf(app)

# CORS configuration
CORS(app, origins=['http://localhost:5000', 'https://your-domain.com'])

# Initialize rate limiter with enhanced configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[
        f"{SecurityConfig.RATE_LIMITS['global_per_minute']} per minute",
        f"{SecurityConfig.RATE_LIMITS['global_per_hour']} per hour"
    ],
    storage_uri="memory://",
    strategy="fixed-window"
)

client = OpenAI()

def log_request(request_id, ip_address, endpoint, status_code, message=""):
    """Log request details for security monitoring."""
    timestamp = datetime.now().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'request_id': request_id,
        'ip_address': ip_address,
        'endpoint': endpoint,
        'status_code': status_code,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'message': message
    }
    logger.info(f"Request: {log_entry}")

def validate_message(message):
    """Enhanced message validation with comprehensive security checks."""
    if not message or not isinstance(message, str):
        return False, "Invalid message format"
    
    # Check message length
    if len(message) > SecurityConfig.MESSAGE_RULES['max_length']:
        return False, f"Message too long (max {SecurityConfig.MESSAGE_RULES['max_length']} characters)"
    
    if len(message) < SecurityConfig.MESSAGE_RULES['min_length']:
        return False, "Message too short"
    
    # Check word count
    word_count = len(message.split())
    if word_count > SecurityConfig.MESSAGE_RULES['max_words']:
        return False, f"Too many words (max {SecurityConfig.MESSAGE_RULES['max_words']})"
    
    # Check for forbidden words
    message_lower = message.lower()
    for word in SecurityConfig.MESSAGE_RULES['forbidden_words']:
        if word in message_lower:
            return False, "Message contains forbidden content"
    
    # Check for malicious patterns
    for pattern in SecurityConfig.FORBIDDEN_PATTERNS:
        if re.search(pattern, message):
            return False, "Message contains potentially harmful content"
    
    # Validate character set
    if not re.match(SecurityConfig.MESSAGE_RULES['allowed_chars'], message):
        return False, "Message contains invalid characters"
    
    return True, None

def sanitize_and_validate_input(data):
    """Sanitize and validate all input data."""
    if not data or not isinstance(data, dict):
        return False, "Invalid request data"
    
    message = data.get('message', '')
    if not message:
        return False, "Message is required"
    
    # Sanitize the message
    sanitized_message = SecurityConfig.sanitize_input(message)
    
    # Validate the sanitized message
    is_valid, error_message = validate_message(sanitized_message)
    if not is_valid:
        return False, error_message
    
    return True, sanitized_message

@app.before_request
def before_request():
    """Security middleware for all requests."""
    request_id = SecurityConfig.generate_request_id()
    request.request_id = request_id
    
    # Validate IP address
    client_ip = get_remote_address()
    if not SecurityConfig.validate_ip(client_ip):
        logger.warning(f"Invalid IP address: {client_ip}")
        return jsonify({'error': 'Invalid request'}), 400
    
    # Log request
    log_request(request_id, client_ip, request.endpoint, None)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@limiter.limit(f"{SecurityConfig.RATE_LIMITS['chat_per_minute']} per minute")
@limiter.limit(f"{SecurityConfig.RATE_LIMITS['chat_per_hour']} per hour")
@limiter.limit(f"{SecurityConfig.RATE_LIMITS['chat_per_day']} per day")
def chat():
    try:
        # Validate and sanitize input
        is_valid, result = sanitize_and_validate_input(request.json)
        if not is_valid:
            log_request(
                getattr(request, 'request_id', 'unknown'),
                get_remote_address(),
                'chat',
                400,
                f"Validation failed: {result}"
            )
            return jsonify({'error': result}), 400
        
        sanitized_message = result
        
        # Get response from OpenAI with timeout and retry logic
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful and friendly AI assistant."},
                    {"role": "user", "content": sanitized_message}
                ],
                max_tokens=SecurityConfig.API_CONFIG['max_tokens'],
                temperature=SecurityConfig.API_CONFIG['temperature'],
                timeout=SecurityConfig.API_CONFIG['timeout']
            )
            
            ai_response = response.choices[0].message.content
            
            # Log successful request
            log_request(
                getattr(request, 'request_id', 'unknown'),
                get_remote_address(),
                'chat',
                200
            )
            
            return jsonify({
                'response': ai_response,
                'request_id': getattr(request, 'request_id', 'unknown')
            })
            
        except Exception as api_error:
            logger.error(f"OpenAI API error: {str(api_error)}")
            return jsonify({
                'error': 'Service temporarily unavailable'
            }), 503
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return jsonify({
            'error': 'Internal server error'
        }), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors."""
    log_request(
        getattr(request, 'request_id', 'unknown'),
        get_remote_address(),
        'chat',
        429,
        "Rate limit exceeded"
    )
    return jsonify({
        'error': 'Rate limit exceeded. Please try again later.',
        'retry_after': e.retry_after if hasattr(e, 'retry_after') else 60
    }), 429

@app.errorhandler(404)
def not_found_handler(e):
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error_handler(e):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False)  # Set debug=False in production 