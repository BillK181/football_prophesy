Imports:
    - Blueprint – Organizes routes into modular components (separates app into smaller parts).
    - request – Handles incoming HTTP request data (form data, query params, etc.).
    - redirect, url_for – Redirect users to other routes using endpoint names.
    - flash – Displays one-time messages (e.g., success/error notifications).
    - render_template – Renders Jinja2 HTML templates.
    - session – Stores user-specific data across requests (e.g., login state, temporary data).
    - func (from SQLAlchemy) – Provides SQL functions (e.g., COUNT, SUM, AVG) for database queries.
    - db – SQLAlchemy database instance used to interact with the database.
    - User – SQLAlchemy model representing users in the database.
Optional Imports:
    - login_required – Decorator from services.auth that restricts routes to authenticated users only.
    - send_welcome_email – Function from services.email_service used to send emails (e.g., after user registration).

Blueprint("auth", __name__)
    - Create a Flask Blueprint for all auth related routes
    - auth_bp groups related routes together and allows them to be registered in app.py as a modular component (optionally with a URL prefix)
    - Blueprints help scale applications by separating concerns (auth, main, API, etc.)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    - Displays register page (GET) and handles user creation (POST)
    - Uses Post → Redirect → Get pattern to prevent duplicate form submissions
    - If the method is POST, I extract submitted form values using request.form
        - .strip() is used to remove leading/trailing whitespace for cleaner input
    - I check if the users username is already taken
        - User.query → start query on User table
        - func.lower(User.username) → convert DB value to lowercase
        - username.lower() → convert input to lowercase
        - == → compare both
        - .first() → return first match or None
        - Prevents Bill and bill being treated as different users
    - I check if the email is already taken with similar code to username check
    - On validation failure, I use redirect instead of render_template to follow the Post → Redirect → Get (PRG) pattern, which prevents duplicate submissions and ensures a clean request cycle
    - I create the new user object and assign it to a variable
    - I call my model method to hash password so I never store plain text passwords
    - I hardcode admin assignment
    - I save new User object to the db
        - db.session.add() stages the object for insertion
        - commit() executes the transaction and persists data to the database
    - I send the welcome email
    - I show the success message and redirect to the login page
        - This prevents form resubmission if user refreshes page
    - Lastly I have the result for a GET request
        - Display registration form
    


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    - Shows login page and logs the user in using Flask-Login
    - Handles redirect back to the page the user originally wanted (next parameter)
    - Uses Post → Redirect → Get pattern to prevent duplicate form submissions
    - Reads the next page from query string: next_page = request.args.get("next")
        - Flask-Login automatically sets this when @login_required redirects to login
    - If the method is POST:
        - Get username and password from the form
        - Query the User table
            - filter_by(username=username).first()
                - Returns first matching user or None
        - Check if user exists and password matches hashed password
            - Uses user.check_password(password)
            - Never stores or compares plain text passwords
        - Logs in the user using Flask-Login: login_user(user)
            - Sets the user as authenticated
            - Flask-Login manages session securely (signed cookie)
        - Redirect to next page if valid:
            - If next_page is missing or unsafe (not starting with "/"), fallback to home page
        - Flash messages can indicate success if desired
    - If login fails:
        - Flash "Invalid username or password"
        - Re-render login form with next parameter preserved
    - For GET request:
        - Render login page with next parameter


@auth_bp.route("/logout")
def logout():
    - Logs the user out using Flask-Login
    - Calls logout_user()
        - Removes authentication state
        - Clears Flask-Login session info
    - Flash a success message: "Logged out successfully!"
    - Redirects to login page