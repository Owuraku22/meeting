from typing import Any, Optional

import frappe


def success_response(
	data: Optional, message: str = "Request Successful", status_code: int = 200, meta: dict | None = None
) -> dict[str, Any]:
	"""Standardized success response format"""

	frappe.local.response["http_status_code"] = status_code

	response = {"success": True, "message": message, "data": data, "status_code": status_code}

	if meta:
		response["meta"] = meta

	return response


def error_message(
	message: str = "An Error Occurred",
	details: Any = None,
	status_code: int = 400,
	error_code: Any | None = None,
) -> dict[str, Any]:
	"""Standardized error response format"""

	frappe.local.response["http_status_code"] = status_code

	response = {"success": False, "message": message, "status_code": status_code}

	if details:
		response["details"] = details

	if error_code:
		response["error_code"] = error_code

	return response


def paginated_response(
	data: list,
	page: int = 1,
	page_size: int = 20,
	total_records: int | None = None,
	message: str = "Success",
	status_code: int = 200,
) -> dict[str, Any]:
	"""Standardized paginated response format"""

	if total_records is None:
		total_records = len(data)

	total_pages = (total_records + page_size - 1) // page_size

	meta = {"page": page, "page_size": page_size, "total_pages": total_pages, "total_records": total_records}

	return success_response(data=data, message=message, status_code=status_code, meta=meta)
