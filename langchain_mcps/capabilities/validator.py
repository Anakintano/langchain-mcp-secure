"""Constraint validation logic for capability-scoped passports."""

from __future__ import annotations
import fnmatch
import os
import time
from typing import Any, Dict, Optional, Tuple

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
            raw_path = tool_params.get("path", "")
            # Canonicalize path to prevent traversal attacks (e.g., /data/../etc/passwd)
            path = os.path.realpath(raw_path) if raw_path else ""
            patterns = constraints["allowed_paths"]
            # Also canonicalize absolute patterns for comparison
            resolved_patterns = [os.path.realpath(p) if os.path.isabs(p) else p for p in patterns]
            if not any(fnmatch.fnmatch(path, p) for p in resolved_patterns):
                return False, f"Path '{raw_path}' (resolved: '{path}') does not match allowed_paths {patterns}"

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

    def validate_time_window(
        self, tool_name: str, current_time: Optional[float] = None
    ) -> Tuple[bool, str]:
        """
        Validate that current time falls within a permission window for the tool.

        If no windows configured, returns (True, "") — always allowed (v1.0/v2.0 compat).
        If windows exist, checks if now >= window.start_time AND now < window.end_time
        for ANY window. Uses OR logic: allowed if in ANY window.

        Args:
            tool_name: Name of the tool.
            current_time: Current time as float seconds (UNIX epoch).
                         Defaults to time.time() if not provided.

        Returns:
            Tuple of (is_valid, reason). reason is empty string on success.
        """
        if current_time is None:
            current_time = time.time()

        windows = self._schema.get_permission_windows(tool_name)
        if windows is None:
            # No time windows configured = always allowed (backward compat)
            return True, ""

        # Check if current_time falls within ANY window [start, end)
        for window in windows:
            start_time = window.get("start_time")
            end_time = window.get("end_time")
            if start_time is not None and end_time is not None:
                if start_time <= current_time < end_time:
                    # In this window, allowed
                    return True, ""

        # Not in any window, denied
        return False, f"current time {current_time} outside all permission windows"

    def validate_permission_gate(
        self,
        tool_name: str,
        gate_config: Dict[str, Any],
        gate_callback: Any = None,
    ) -> Tuple[bool, str]:
        """
        Validate a permission gate via external callback.

        Permission gates require external approval (e.g., webhook, manual review).
        The gate_callback is responsible for returning (is_allowed, reason).

        Args:
            tool_name: Name of the tool.
            gate_config: Gate configuration dict.
            gate_callback: Callback function(tool_name, gate_config) -> (bool, str).
                          Required to validate gate.

        Returns:
            Tuple of (is_valid, reason).
        """
        if gate_callback is None:
            return False, f"permission gate for '{tool_name}' requires callback but none provided"

        try:
            is_allowed, reason = gate_callback(tool_name, gate_config)
            return is_allowed, reason
        except Exception as e:
            error_str = str(e)
            return False, f"permission gate callback failed: {error_str}"

    def validate_data_provenance(
        self,
        tool_name: str,
        tool_output: Any,
        provenance_metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Validate tool output against data provenance constraints before the LLM
        processes it.

        Guards against:
        - Data arriving from untrusted/unallowed sources (IPI via data channel).
        - Forbidden multimodal content types (adversarial images/audio).

        Constraint format (in passport capabilities)::

            "file_read": {
                "allowed": True,
                "constraints": {
                    "data_provenance": {
                        "allowed_sources": ["s3://trusted-bucket"],
                        "forbidden_content_types": ["image", "audio"],
                        "require_provenance_tag": True
                    }
                }
            }

        Args:
            tool_name: Name of the tool that produced the output.
            tool_output: The data returned by the tool.
            provenance_metadata: Optional dict with at least a "source" key.

        Returns:
            True if the output is safe to forward to the LLM.

        Raises:
            PermissionError: If provenance validation fails.
        """
        constraints = self._schema.get_constraints(tool_name)
        prov_config = constraints.get("data_provenance")
        if not prov_config:
            return True  # No provenance constraint — allow

        allowed_sources = prov_config.get("allowed_sources", [])
        forbidden_types = prov_config.get("forbidden_content_types", [])
        require_tag = prov_config.get("require_provenance_tag", False)

        # Source check
        if provenance_metadata is not None:
            source = provenance_metadata.get("source")
            if allowed_sources and source not in allowed_sources:
                raise PermissionError(
                    f"Source '{source}' not in allowed_sources {allowed_sources} for '{tool_name}'"
                )
        elif require_tag:
            raise PermissionError(
                f"Provenance metadata required but not provided for '{tool_name}'"
            )

        # Content-type check (multimodal filtering)
        if isinstance(tool_output, dict) and "content_type" in tool_output:
            content_type = tool_output["content_type"]
            if content_type in forbidden_types:
                raise PermissionError(
                    f"Content type '{content_type}' is forbidden for '{tool_name}'"
                )

        return True
