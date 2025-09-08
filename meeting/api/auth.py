import frappe
from frappe.auth import LoginManager

from meeting.api.validators import validate_request
from meeting.utils.responses import error_message, success_response


@frappe.whitelist(allow_guest=True)
def login(email, password):
	try:
		# Authenticate User
		LoginManager()
		frappe.auth.LoginManager().authenticate(email, password)

		required_fields = ["email", "password"]
		validation_results = validate_request(frappe.local.form_dict, required_fields)

		# Validate request data
		if not validation_results["valid"]:
			return error_message("Validation Error", details=validation_results["errors"], status_code=400)

		if not email or not password:
			return error_message("Email and password are required", status_code=400)

		user = email.strip().lower()
		if not frappe.local.db.exists("User", email):
			return error_message("User does not exist", status_code=401)

		# Generate Bearer Token
		user_doc = frappe.get_doc("User", user)

		if not user_doc.api_key:
			api_key = frappe.generate_hash(length=15)
			api_secret = frappe.generate_hash(length=15)

			user_doc.api_key = api_key
			user_doc.api_secret = api_secret
			user_doc.save(ignore_permissions=True)

		# Create bearer Token combine api_key and api_secret and encode it to base64
		import base64

		token_string = f"{user_doc.api_key}:{user_doc.api_secret}"
		bearer_token = base64.b64encode(token_string.encode()).decode()

		return success_response(
			message="Login successful",
			data={
				"token": bearer_token,
				"user": {
					"email": user_doc.email,
					"first_name": user_doc.first_name,
					"last_name": user_doc.last_name,
					"phone": user_doc.phone,
				},
			},
			status_code=200,
		)
	except Exception as e:
		frappe.log_error(frappe.get_traceback(), "Login Error")
		return error_message("An error occurred during login", details=str(e), status_code=500)


@frappe.whitelist(allow_guest=True)
def signup(full_name, email, password, phone):
	try:
		required_fields = ["full_name", "email", "password", "phone"]
		validation_reslults = validate_request(frappe.local.form_dict, required_fields)

		# Validate request data
		if not validation_reslults["valid"]:
			return error_message("Validation Error", details=validation_reslults["errors"], status_code=400)

		# Check if user already exists
		if frappe.db.exists("User", {"email": email, "phone": phone}):
			return error_message("User already exists", status_code=400)

		# Create new user
		user = frappe.get_doc(
			{
				"doctype": "User",
				"first_name": full_name,
				"email": email,
				"phone": phone,
				"new_password": password,
				"enabled": 1,
				"user_type": "System User",
			}
		)
		user.insert(ignore_permissions=True)
		frappe.db.commit()

		## Generate Bearer Token
		user_model = frappe.get_doc("User", email)

		if not user_model.api_key:
			api_key = frappe.generate_hash(length=50)
			api_secret = frappe.generate_hash(length=50)

			user_model.api_key = api_key
			user_model.api_secret = api_secret
			user_model.save(ignore_permissions=True)

		# Create bearer Token combine api_key and api_secret and encode it to base64
		import base64

		token_string = f"{user_model.api_key}:{user_model.api_secret}"
		bearer_token = base64.b64encode(token_string.encode()).decode()

		return success_response(
			message="Signup successful",
			data={
				"token": bearer_token,
				"user": {
					"email": user.email,
					"first_name": user.first_name,
					"last_name": user.last_name,
					"phone": user.phone,
				},
			},
			status_code=201,
		)
	except Exception as e:
		frappe.log_error(frappe.get_traceback(), "Signup Error")
		return error_message("An error occurred during signup", details=str(e), status_code=500)


@frappe.whitelist(allow_guest=True)
def logout():
	try:
		if frappe.session.user == "Guest":
			return error_message("User is not logged in", status_code=401)

		frappe.local.login_manager.logout()
		return success_response(message="Logout successful", status_code=200)
	except frappe.exceptions.AuthenticationError:
		return error_message("User is not logged in", status_code=401)
	except Exception as e:
		return error_message("An error occurred during logout", details=str(e), status_code=500)


@frappe.whitelist(allow_guest=True)
def verify_token():
	"""Verify bearer token endpoint"""
	try:
		user = frappe.session.user
		if user == "Guest":
			return error_message(message="Invalid or expired token", status_code=401)

		user_doc = frappe.get_doc("User", user)
		return success_response(
			data={
				"user": user_doc.name,
				"full_name": user_doc.full_name,
				"roles": [role.role for role in user_doc.roles],
			},
			message="Token is valid",
		)
	except Exception as e:
		return error_message(message="Token verification failed", details=str(e), status_code=500)


def authenticate_bearer_token():
	"""Custom authentication for bearer tokens"""
	auth_header = frappe.get_request_header("Authorization")

	if not auth_header or not auth_header.startswith("Bearer "):
		return None

	try:
		import base64

		token = auth_header.split(" ")[1]
		decoded_token = base64.b64decode(token).decode()
		api_key, api_secret = decoded_token.split(":")

		# Authenticate using frappe's API key system
		user = frappe.db.get_value("User", {"api_key": api_key, "api_secret": api_secret})

		if user:
			frappe.set_user(user)
			return user

	except Exception:
		pass

	return None
