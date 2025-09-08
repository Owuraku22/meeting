from typing import Any

import frappe


def validate_request(
	data: dict[str, Any], required_fields: list[str], optional_fields: list[str] | None = None
) -> dict[str, Any]:
	"""
	Custom request validator to avoid repetitive if statements

	Args:
		data: Request data dictionary
		required_fields: List of required field names
		optional_fields: List of optional field names

	Returns:
		Dictionary with validation results
	"""
	errors = []
	warnings = []

	# Check required fields
	for field in required_fields:
		if field not in data or data[field] is None or data[field] == "":
			errors.append(f"'{field}' is required")

	# Check for unexpected fields (optional validation)
	if optional_fields is not None:
		allowed_fields = set(required_fields + optional_fields)
		unexpected_fields = set(data.keys()) - allowed_fields

		if unexpected_fields:
			warnings.append(f"Unexpected fields: {', '.join(unexpected_fields)}")

	return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "data": data}


def validate_email(email: str) -> bool:
	"""Validate email format"""
	import re

	email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
	return bool(re.match(email_regex, email))


def validate_datetime(datetime_str: str) -> bool:
	"""Validate datetime format"""
	try:
		frappe.utils.get_datetime(datetime_str)
		return True
	except ValueError:
		return False


class RequestValidator:
	"""Advanced request validator class"""

	def __init__(self, data: dict[str, Any]):
		self.data = data
		self.errors = []
		self.warnings = []

	def require(self, *fields) -> "RequestValidator":
		"""Add required fields"""
		for field in fields:
			if field not in self.data or not self.data[field]:
				self.errors.append(f"'{field}' is required")
		return self

	def email(self, field: str) -> "RequestValidator":
		"""Validate email field"""
		if self.data.get(field):
			if not validate_email(self.data[field]):
				self.errors.append(f"'{field}' must be a valid email")
		return self

	def datetime_field(self, field: str) -> "RequestValidator":
		"""Validate datetime field"""
		if self.data.get(field):
			if not validate_datetime(self.data[field]):
				self.errors.append(f"'{field}' must be a valid datetime")
		return self

	def min_length(self, field: str, length: int) -> "RequestValidator":
		"""Validate minimum length"""
		if self.data.get(field):
			if len(str(self.data[field])) < length:
				self.errors.append(f"'{field}' must be at least {length} characters")
		return self

	def is_valid(self) -> bool:
		"""Check if validation passed"""
		return len(self.errors) == 0

	def get_result(self) -> dict[str, Any]:
		"""Get validation result"""
		return {"valid": self.is_valid(), "errors": self.errors, "warnings": self.warnings, "data": self.data}
