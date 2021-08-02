from flask import Flask, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import redirect
from auxiliar import login_required, iscoord
import sqlite3
from tempfile import mkdtemp

app = Flask(__name__)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.route('/')
@login_required
def index():
    location = ''

    with sqlite3.connect('weather.db') as con:
        cur = con.cursor()
            
        cur.execute('SELECT location FROM users WHERE id = ?', [session['user_id']])
        res = cur.fetchall()[0][0]
        location = res
            
        con.commit()

    return render_template('index.html', location=location)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        with sqlite3.connect('weather.db') as con:
            cur = con.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            res = cur.fetchall()
            
            if not res:
                return render_template('login.html', err="Can't find the username")

            hashed = res[0][2]
            user_id = res[0][0]

            if check_password_hash(hashed, password):
                session['user_id'] = user_id
                con.commit()
                return redirect('/')
            else:
                con.commit()
                return render_template('login.html', err='Password is incorrect')
    else:
        return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        location = request.form.get('location')

        lat = request.form.get('lat')
        lon = request.form.get('lon')

        if not location:
            return render_template('register.html', err='You need to specify a location')

        if location == 'custom-coords':
            if not lat or not lon:
                return render_template('register.html', err='Blank latitude or longitude')
            
            if not iscoord(lat) or not iscoord(lon):
                return render_template('register.html', err='Invalid latitude or longitude')

        coords = f'{lat},{lon}'

        if not username:
            return render_template('register.html', err='Invalid username')
        elif not password:
            return render_template('register.html', err='Invalid password')
        elif password != confirm:
            return render_template('register.html', err="Passwords don't match")

        hash = generate_password_hash(password)

        with sqlite3.connect('weather.db') as con:
            cur = con.cursor()
            cur.execute('SELECT username FROM users WHERE username = ?', (username,))
            res = cur.fetchall()
            
            if res:
                return render_template('register.html', err="Username is taken")

            if location == 'custom-coords':
                cur.execute('INSERT INTO users (username, hash, location) VALUES (?, ?, ?)', (username, hash, coords))
            else:
                cur.execute('INSERT INTO users (username, hash, location) VALUES (?, ?, ?)', (username, hash, location))
            
            con.commit()
        
        return redirect('/login')

    else:
        return render_template('register.html')


@app.route('/change_profile', methods=['GET','POST'])
def change_profile():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_username = request.form.get('new_username')
        new_password = request.form.get('new_password')
        new_location = request.form.get('new_location')

        if not new_username and not new_password and not new_location:
            return render_template('change_profile.html', err='No info was given')

        lat = request.form.get('lat')
        lon = request.form.get('lon')

        with sqlite3.connect('weather.db') as con:
            cur = con.cursor()
            cur.execute('SELECT hash FROM users WHERE id = ?', (session['user_id'],))
            res = cur.fetchone()
            
            if not check_password_hash(res[0], old_password):
                return render_template('change_profile.html', err='Old password is incorrect')

            cur.execute('SELECT username FROM users WHERE username = ?', (new_username,))
            res = cur.fetchone()
            
            cur.execute('SELECT username FROM users WHERE id = ?', (session['user_id'],))
            session_user = cur.fetchone()

            if res and res != session_user:
                return render_template('change_profile.html', err="Username is taken")

            if new_location == 'custom-coords':
                if not lat or not lon:
                    return render_template('change_profile.html', err='Blank latitude or longitude')
                
                if not iscoord(lat) or not iscoord(lon):
                    return render_template('change_profile.html', err='Invalid latitude or longitude')  

            new_hashed = generate_password_hash(new_password)
            new_coords = f'{lat},{lon}'

            if new_username and new_password and new_location == 'custom-coords':
                cur.execute('UPDATE users SET username = ?, hash = ?, location = ? WHERE id = ?', (new_username, new_hashed, new_coords, session['user_id'],))
            
            elif new_username and new_password and new_location == 'actual-location':
                cur.execute('UPDATE users SET username = ?, hash = ?, location = ? WHERE id = ?', (new_username, new_hashed, new_location, session['user_id'],))
            
            elif new_username and new_password and not new_location:
                cur.execute('UPDATE users SET username = ?, hash = ? WHERE id = ?', (new_username, new_hashed, session['user_id'],))
           
            elif new_username and not new_password and new_location == 'custom-coords':
                cur.execute('UPDATE users SET username = ?, location = ? WHERE id = ?', (new_username, new_coords, session['user_id'],))
           
            elif new_username and not new_password and new_location == 'actual-location':
                cur.execute('UPDATE users SET username = ?, location = ? WHERE id = ?', (new_username, new_location, session['user_id'],))
         
            elif not new_username and new_password and new_location == 'custom-coords':
                cur.execute('UPDATE users SET hash = ?, location = ? WHERE id = ?', (new_hashed, new_coords, session['user_id'],))

            elif not new_username and new_password and new_location == 'actual-location':
                cur.execute('UPDATE users SET hash = ?, location = ? WHERE id = ?', (new_hashed, new_location, session['user_id'],))

            elif new_username and not new_password and not new_location:
                cur.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, session['user_id'],))

            elif not new_username and new_password and not new_location:
                cur.execute('UPDATE users SET hash = ? WHERE id = ?', (new_hashed, session['user_id'],))

            elif not new_username and not new_password and new_location == 'custom-coords':
                cur.execute('UPDATE users SET location = ? WHERE id = ?', (new_coords, session['user_id'],))

            elif not new_username and not new_password and new_location == 'actual-location':
                cur.execute('UPDATE users SET location = ? WHERE id = ?', (new_location, session['user_id'],))

            con.commit()

        return redirect('/')

    else:
        return render_template('change_profile.html')


@app.route('/logout')
def logout():
    session['user_id'] = None
    return redirect('/')
