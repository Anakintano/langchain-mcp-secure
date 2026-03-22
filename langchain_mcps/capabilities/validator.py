"""Constraint validation logic for capability-scoped passports."""

from __future__ import annotations
import fnmatch
from typing import Any, Dict, Tuple

from .schema import CapabilitySchema


class CapabilityValidator:
    """
    Validates tool call parameters against capability constraints.

    Supported constraint types:
    - allowed_tables: tool_params["table"] must be in the list
    - recipient_domains: tool_params["recipient"] domain must be in allowlist
    - allowed_paths: tool_params["path"] must match at least one glob pattern
    - max_rows_per_query: tool_params["limit"] must be <= max
    - max_file_size_mb: tool_params["size_mb"] must be <= max
    """

    def __init__(self, schema: CapabilitySchema) -> None:
        """
        Args:
            schema: The CapabilitySchema to validate against.
        """
        self._schema = schema

    def validate_tool_call(
        self, tool_name: str, tool_params: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """
        Validate a tool call against capability constraints.

        Args:
            tool_name: Name of the tool being called.
            tool_params: Parameters passed to the tool.

        Returns:
            Tuple of (is_valid, reason). reason is empty string on success.
        """
        if not self._schema.is_tool_allowed(tool_name):
            return False, f"Tool '{tool_name}' is not allowed by passport capabilities"

        constraints = self._schema.get_constraints(tool_name)

        # allowed_tables
        if "allowed_tables" in constraints:
            table = tool_params.get("table")
            allowed = constraints["allowed_tables"]
            if table not in allowed:
                return False, f"Table '{table}' not in allowed_tables {allowed}"

        # recipient_domains
        if "recipient_domains" in constraints:
            recipient = tool_params.get("recipient", "")
            domain = recipient.split("@")[-1] if "@" in recipient else recipient
            allowed_domains = constraints["recipient_domains"]
            if domain not in allowed_domains:
                return False, f"Recipient domain '{domain}' not in allowed_domains {allowed_domains}"

        # allowed_paths
        if "allowed_paths" in constraints:
            path = tool_params.get("path", "")
            patterns = constraints["allowed_paths"]
            if not any(fnmatch.fnmatch(path, p) for p in patterns):
                return False, f"Path '{path}' does not match allowed_paths {patterns}"

        # max_rows_per_query
        if "max_rows_per_query" in constraints:
            limit = tool_params.get("limit")
            max_rows = constraints["max_rows_per_query"]
            if limit is not None and limit > max_rows:
                return False, f"Query limit {limit} exceeds max_rows_per_query {max_rows}"

        # max_file_size_mb
        if "max_file_size_mb" in constraints:
            size_mb = tool_params.get("size_mb")
            max_size = constraints["max_file_size_mb"]
            if size_mb is not None and size_mb > max_size:
                return False, f"File size {size_mb}MB exceeds max_file_size_mb {max_size}MB"

        return True, ""
