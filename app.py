from flask import Flask, render_template, request
from hashlib import sha256
from PasswordCheckerPhase3.backend.passwordCheckerPhase3 import passwordChecker


app = Flask(__name__, template_folder='frontend/templates', static_folder='frontend/static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['GET','POST'])
def check_password():
    if request.method == 'POST':
        password = request.form.get('password')

        hashed_password = request.form.get('hashed_password')

        server_hashed_password = sha256(password.encode()).hexdigest()

        if server_hashed_password != hashed_password:
            return render_template('passwordChecker.html', error="Password does not match "
                                                                 "the hashed password.")

        result = passwordChecker(password)

        strength_message = {
            "Very strong": "Your password is very strong. Excellent choice!",
            "Strong": "Your password is strong. Good job!",
            "Medium": "Your password is medium. Consider making it stronger.",
            "Weak": "Your password is weak. Please consider improving it.",
            "Very weak": "Your password is very weak. It needs significant improvement."
        }

        return render_template('results.html',
                               strength = result['strength'],
                               strength_message = strength_message[result['strength']],
                               is_pwned = result['pwned'],
                               entropy = result['entropy'])

    return render_template('passwordChecker.html')

@app.route('/help')
def help():
    return render_template('help.html')


if __name__ == '__main__':
    app.run(debug=True)
