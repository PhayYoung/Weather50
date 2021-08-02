from functools import wraps
from flask import redirect, session
from werkzeug.security import check_password_hash, generate_password_hash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def iscoord(n):
    try:
        return -90.0 <= float(n) <= 90.0

    except:
        return False




