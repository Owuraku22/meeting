import base64

import frappe
from frappe import _


@frappe.whitelist(allow_guest=True)
def login(email, password):
	try:
		user = frappe.db.get_value("User", {"email": email}, ["name", "enabled", "email"], as_dict=True)
		if not user or not user.enabled:
			return {"status": "401", "message": _("Invalid login credentials")}
		frappe.local.login_manager.authenticate(email, password)
		frappe.local.login_manager.post_login()
		token = base64.b64encode(frappe.session.sid.encode()).decode()
		return {
			"status": "200",
			"message": _("Logged In"),
			"user_name": user.get("name"),
			"user_email": user.get("email", email),
			"token": token,
		}
	except Exception as e:
		return {"status": "500", "message": _(f"Login failed: {e}")}


@frappe.whitelist(allow_guest=True)
def signup(email, password, first_name, last_name):
	try:
		if frappe.db.exists("User", {"email": email}):
			return {"status": "409", "message": _("User already exists")}

		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": email,
				"first_name": first_name,
				"last_name": last_name,
				"enabled": 1,
				"new_password": password,
				"user_type": "Website User",
			}
		)

		print(user)

		user.flags.ignore_permissions = True
		user.insert()
		frappe.local.login_manager.authenticate(email, password)
		frappe.local.login_manager.post_login()
		token = base64.b64encode(frappe.session.sid.encode()).decode()

		return {
			"status": "201",
			"message": _("User Sign Up successfully"),
			"user_email": user.email,
			"token": token,
		}

	except Exception as e:
		return {"status": "500", "message": _(f"Signup failed: {e}")}


def get_bearer_token_from_header():
	auth_header = frappe.get_request_header("Authorization")
	if auth_header and auth_header.startswith("Bearer "):
		return auth_header.split("Bearer ", 1)[1]
	return None
