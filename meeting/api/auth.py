import frappe
from frappe import auth

from meeting.api.validators import validate_request
from meeting.utils.responses import error_message, success_response


@frappe.whitelist(allow_guest=True)
def login():
	try:
		required_fields = ["email", "password"]
		validation_results = validate_request(frappe.local.fromDict, required_fields)

		# Validate request data
		if not validation_results["valid"]:
			return error_message("Validation Error", details=validation_results["errors"], status_code=400)

		# Authenticate User
		user = frappe.local.fromDict.get("email")
		password = frappe.local.fromDict.get("password")

		try:
			frappe.local.login_manager.login(user, password)
			frappe.local.login_manager.post_login()
		except frappe.exceptions.AuthenticationError:
			return error_message("Invalid login credentials", status_code=401)

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

		token_string = f"{user_doc.api_key}:{user_doc.api_secret}=="
		bearer_token = base64.b64encode(token_string.encode()).decode()

		return success_response(
			data={
				"token": bearer_token,
				"user": {
					"email": user_doc.email,
					"first_name": user_doc.first_name,
					"last_name": user_doc.last_name,
					"phone": user_doc.phone,
					"roles": user_doc.get("roles"),
				},
				"message": "Login successful",
			}
		)
	except Exception as e:
		frappe.log_error(frappe.get_traceback(), "Login Error")
		return error_message("An error occurred during login", details=str(e), status_code=500)


@frappe.whitelist(allow_guest=True)
def logout():
	try:
		frappe.local.login_manager.logout()
		return success_response([], "logout successful")
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
