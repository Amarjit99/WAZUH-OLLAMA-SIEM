"""Analyst-Approved Active Response and Containment Playbook Service."""

from datetime import datetime, timezone
import ipaddress
import logging
import re
import uuid
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.errors import AppException
from app.repositories.audit_repository import AuditRepository
from app.schemas.containment import (
    ContainmentActionType,
    ContainmentExecutionRequest,
    ContainmentExecutionResponse,
    ContainmentPlatform,
    ContainmentProposalRequest,
    ContainmentProposalResponse,
    GeneratedCommand,
    ProposedContainmentAction,
)
from app.schemas.error import ErrorCode

logger = logging.getLogger("siem.containment_service")


class ContainmentService:
    """Provides human-in-the-loop active response command generation and audited approval."""

    def __init__(self, settings: Settings, audit_repository: Optional[AuditRepository] = None):
        self.settings = settings
        self.audit_repository = audit_repository or AuditRepository()

    @staticmethod
    def _validate_and_sanitize_ip(ip_str: str) -> str:
        """Validate IP string using standard library and prevent self-lockout."""
        clean_ip = ip_str.strip()
        try:
            ip_obj = ipaddress.ip_address(clean_ip)
        except ValueError as err:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid IP address format: '{clean_ip}'",
                status_code=400,
            ) from err

        if ip_obj.is_loopback:
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="Cannot contain loopback address (127.0.0.1 / ::1)",
                status_code=400,
            )

        return str(ip_obj)

    @staticmethod
    def _sanitize_identifier(target: str) -> str:
        """Ensure host or process identifiers contain only safe characters."""
        clean = target.strip()
        if not clean or not re.match(r"^[a-zA-Z0-9_\-\.\:\/]+$", clean):
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message=f"Invalid target identifier: '{clean}'",
                status_code=400,
            )
        return clean

    def generate_commands_for_action(
        self, action_type: ContainmentActionType, target: str
    ) -> List[GeneratedCommand]:
        """Generate platform-tailored executable containment rules."""
        if action_type == ContainmentActionType.BLOCK_IP:
            clean_ip = self._validate_and_sanitize_ip(target)
            return [
                GeneratedCommand(
                    platform=ContainmentPlatform.LINUX_IPTABLES,
                    command=f"sudo iptables -I INPUT -s {clean_ip} -j DROP",
                    description=f"Drop all inbound traffic from {clean_ip} via netfilter iptables",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.LINUX_NFTABLES,
                    command=f"sudo nft add rule inet filter input ip saddr {clean_ip} drop",
                    description=f"Modern nftables drop rule for {clean_ip}",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.WINDOWS_NETSH,
                    command=f'netsh advfirewall firewall add rule name="SIEM-Block-{clean_ip}" dir=in action=block remoteip={clean_ip}',
                    description=f"Windows Advanced Firewall inbound block rule for {clean_ip}",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.WAZUH_ACTIVE_RESPONSE,
                    command=f"/var/ossec/active-response/bin/firewall-drop.sh add - {clean_ip}",
                    description=f"Trigger Wazuh Active Response firewall-drop script against {clean_ip}",
                ),
            ]

        elif action_type == ContainmentActionType.ISOLATE_HOST:
            clean_host = self._sanitize_identifier(target)
            return [
                GeneratedCommand(
                    platform=ContainmentPlatform.WAZUH_ACTIVE_RESPONSE,
                    command=f"/var/ossec/bin/agent_control -b {clean_host}",
                    description=f"Quarantine and network isolate agent {clean_host} via Wazuh controller",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.WINDOWS_NETSH,
                    command='netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound',
                    description=f"Quarantine host {clean_host} by blocking all inbound and outbound traffic except management",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.LINUX_IPTABLES,
                    command="sudo iptables -P INPUT DROP && sudo iptables -P OUTPUT DROP",
                    description=f"Drop all network communication on host {clean_host}",
                ),
            ]

        elif action_type == ContainmentActionType.KILL_PROCESS:
            clean_proc = self._sanitize_identifier(target)
            return [
                GeneratedCommand(
                    platform=ContainmentPlatform.LINUX_IPTABLES,
                    command=f'sudo pkill -9 -f "{clean_proc}"',
                    description=f"Send SIGKILL to terminate all instances of {clean_proc} on Linux",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.WINDOWS_NETSH,
                    command=f'taskkill /F /IM "{clean_proc}" /T',
                    description=f"Forcefully terminate {clean_proc} and child process tree on Windows",
                ),
            ]

        elif action_type == ContainmentActionType.DISABLE_USER:
            clean_user = self._sanitize_identifier(target)
            return [
                GeneratedCommand(
                    platform=ContainmentPlatform.LINUX_IPTABLES,
                    command=f"sudo usermod -L {clean_user} && sudo pkill -u {clean_user}",
                    description=f"Lock account and kill all active shell sessions for user {clean_user}",
                ),
                GeneratedCommand(
                    platform=ContainmentPlatform.WINDOWS_NETSH,
                    command=f"net user {clean_user} /active:no",
                    description=f"Disable Windows domain/local user account {clean_user}",
                ),
            ]

        return []

    def propose_containment(self, request: ContainmentProposalRequest) -> ContainmentProposalResponse:
        """Formulate recommended containment options based on available alert context."""
        proposed: List[ProposedContainmentAction] = []

        # If malicious source IP is present, propose network block
        if request.source_ip:
            try:
                clean_ip = self._validate_and_sanitize_ip(request.source_ip)
                commands = self.generate_commands_for_action(ContainmentActionType.BLOCK_IP, clean_ip)
                proposed.append(
                    ProposedContainmentAction(
                        action_type=ContainmentActionType.BLOCK_IP,
                        target=clean_ip,
                        rationale=f"Inbound traffic from external or untrusted source IP {clean_ip} is triggering security alerts.",
                        risk_level="LOW",
                        commands=commands,
                    )
                )
            except AppException:
                pass

        # If compromised agent or host is present, propose host isolation
        target_host = request.agent_name or request.agent_id
        if target_host:
            try:
                clean_host = self._sanitize_identifier(target_host)
                commands = self.generate_commands_for_action(ContainmentActionType.ISOLATE_HOST, clean_host)
                proposed.append(
                    ProposedContainmentAction(
                        action_type=ContainmentActionType.ISOLATE_HOST,
                        target=clean_host,
                        rationale=f"Compromised host {clean_host} exhibiting severe rootkit, ransomware, or persistence activity.",
                        risk_level="MEDIUM",
                        commands=commands,
                    )
                )
            except AppException:
                pass

        # If process name is present, propose process termination
        if request.process_name:
            try:
                clean_proc = self._sanitize_identifier(request.process_name)
                commands = self.generate_commands_for_action(ContainmentActionType.KILL_PROCESS, clean_proc)
                proposed.append(
                    ProposedContainmentAction(
                        action_type=ContainmentActionType.KILL_PROCESS,
                        target=clean_proc,
                        rationale=f"Malicious executable process {clean_proc} identified in event telemetry.",
                        risk_level="LOW",
                        commands=commands,
                    )
                )
            except AppException:
                pass

        return ContainmentProposalResponse(
            proposed_actions=proposed,
            generated_at=datetime.now(timezone.utc),
        )

    async def approve_and_log_containment(
        self,
        request: ContainmentExecutionRequest,
        session: AsyncSession,
        request_id: str,
        client_ip: str,
    ) -> ContainmentExecutionResponse:
        """Enforce human authorization gate, generate containment rules, and commit to cryptographic audit log."""
        if not request.analyst_approval:
            logger.warning(
                "Containment execution rejected: analyst_approval is False for target %s",
                request.target,
            )
            raise AppException(
                code=ErrorCode.VALIDATION_ERROR,
                message="Human analyst approval is required to authorize containment action.",
                status_code=400,
            )

        execution_id = f"containment-{uuid.uuid4().hex[:12]}"
        commands = self.generate_commands_for_action(request.action_type, request.target)

        metadata = {
            "execution_id": execution_id,
            "action_type": request.action_type.value,
            "target": request.target,
            "analyst_id": request.analyst_id,
            "rationale": request.rationale,
            "alert_id": request.alert_id,
            "investigation_id": request.investigation_id,
            "commands_count": len(commands),
        }

        # Commit to SHA-256 tamper-evident audit chain
        audit_event = await self.audit_repository.log_event(
            session=session,
            actor_id=request.analyst_id,
            action=f"CONTAINMENT_{request.action_type.value}_APPROVED",
            resource_type="CONTAINMENT",
            resource_id=execution_id,
            outcome="SUCCESS",
            request_id=request_id,
            client_ip=client_ip,
            metadata=metadata,
        )
        await session.commit()

        logger.info(
            "Containment action %s approved by %s for %s (Audit ID: %s)",
            request.action_type.value,
            request.analyst_id,
            request.target,
            audit_event.audit_id,
        )

        return ContainmentExecutionResponse(
            execution_id=execution_id,
            action_type=request.action_type,
            target=request.target,
            status="APPROVED_AND_LOGGED",
            generated_commands=commands,
            audit_id=audit_event.audit_id,
            approved_at=datetime.now(timezone.utc),
            analyst_id=request.analyst_id,
            message=f"Containment action authorized. Cryptographically audited under Audit ID {audit_event.audit_id}.",
        )
