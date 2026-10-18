"""
Agent Adapter (PRD Section 12.1).
Converts tool requests from AI agents into the standardized Prompt Aegis format,
intercepts executions through the governance layer, and supports wrapping Python
function-calling tools.

Standard format (PRD §12.1):
{
  "agent_id": "agent_001",
  "user_id": "user_123",
  "tool": "database.search",
  "arguments": {
    "query": "invoice_1024"
  },
  "timestamp": "2026-09-26T12:30:00Z"
}
"""
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from pydantic import BaseModel, Field

from governance.interceptor import intercept


class StandardToolRequest(BaseModel):
    agent_id: str
    user_id: str = ""
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class AgentAdapter:
    """
    Adapter connecting AI agent frameworks and function-calling agents
    to the Prompt Aegis governance gateway.
    """

    def __init__(self, agent_id: str, default_user_id: str = "", configuration: str = "full"):
        self.agent_id = agent_id
        self.default_user_id = default_user_id
        self.configuration = configuration

    def format_request(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Convert an agent tool request into the standardized PRD §12.1 format."""
        req = StandardToolRequest(
            agent_id=self.agent_id,
            user_id=user_id if user_id is not None else self.default_user_id,
            tool=tool_name,
            arguments=arguments,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        payload = req.model_dump()
        payload["context"] = context or {}
        return payload

    def execute_tool_call(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        user_id: Optional[str] = None,
        configuration: Optional[str] = None,
        experiment_run_id: str = "",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standardizes the request, routes it through the Prompt Aegis interceptor,
        and returns the decision packet.
        """
        config = configuration or self.configuration
        uid = user_id if user_id is not None else self.default_user_id

        # Authorization uses the exact registered identifier. Stripping a
        # namespace could map distinct tools onto the same permission record.
        standard_req = self.format_request(tool_name, arguments, user_id=uid, context=context)

        result = intercept(
            agent_id=self.agent_id,
            tool_name=tool_name,
            arguments=arguments,
            user_id=uid,
            configuration=config,
            experiment_run_id=experiment_run_id,
            context=context,
        )

        return {
            "request": standard_req,
            "governance": result,
            "allowed": result["decision"] == "ALLOW",
        }

    def wrap_tool(self, tool_name: str, tool_func: Callable[..., Any]) -> Callable[..., Any]:
        """
        Decorator / wrapper that guards any Python callable tool with Prompt Aegis governance.
        If the tool call is denied or blocked, raises PermissionError with the gateway reason.
        """
        def guarded(*args, **kwargs):
            # Extract arguments as dictionary
            arguments = kwargs.copy()
            if args:
                arguments["_args"] = list(args)

            eval_res = self.execute_tool_call(tool_name, arguments)
            decision = eval_res["governance"]["decision"]
            reason = eval_res["governance"]["reason"]

            if decision != "ALLOW":
                raise PermissionError(f"Prompt Aegis Blocked Tool Call [{decision}]: {reason}")

            return tool_func(*args, **kwargs)

        return guarded
