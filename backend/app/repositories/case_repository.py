"""Repository for Case Management database operations."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.case import Case, generate_case_id

logger = logging.getLogger("siem.case_repository")


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class CaseRepository:
    """Encapsulates all database operations for Case Management."""

    async def create_case(
        self,
        session: AsyncSession,
        title: str,
        description: Optional[str] = None,
        priority: str = "medium",
        assignee: Optional[str] = None,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        analyst_notes: Optional[str] = None,
    ) -> Case:
        """Create a new Case record."""
        case = Case(
            case_id=generate_case_id(),
            title=title.strip(),
            description=description.strip() if description else None,
            status="open",
            priority=priority.lower(),
            assignee=assignee.strip() if assignee else None,
            alert_id=alert_id.strip() if alert_id else None,
            investigation_id=investigation_id.strip() if investigation_id else None,
            analyst_notes=analyst_notes.strip() if analyst_notes else None,
            created_at=utc_now(),
            updated_at=utc_now(),
        )
        session.add(case)
        await session.flush()
        return case

    async def get_case_by_id(
        self,
        session: AsyncSession,
        case_id: str,
    ) -> Optional[Case]:
        """Retrieve a single active case by ID."""
        stmt = (
            select(Case)
            .options(selectinload(Case.investigation))
            .where(
                Case.case_id == case_id,
                Case.deleted_at.is_(None),
            )
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_cases(
        self,
        session: AsyncSession,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
        alert_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 25,
        sort_order: str = "desc",
    ) -> Tuple[List[Case], int]:
        """Query paginated active cases with bounded filtering."""
        conditions = [Case.deleted_at.is_(None)]

        if status:
            conditions.append(Case.status == status.lower())
        if priority:
            conditions.append(Case.priority == priority.lower())
        if assignee:
            conditions.append(Case.assignee.ilike(f"%{assignee.strip()}%"))
        if alert_id:
            conditions.append(Case.alert_id == alert_id.strip())
        if start_time:
            conditions.append(Case.created_at >= start_time)
        if end_time:
            conditions.append(Case.created_at <= end_time)

        # Count total matching
        count_stmt = select(func.count(Case.case_id)).where(*conditions)
        total_count = (await session.execute(count_stmt)).scalar_one()

        # Query items
        order_col = Case.created_at.asc() if sort_order.lower() == "asc" else Case.created_at.desc()
        query_stmt = (
            select(Case)
            .options(selectinload(Case.investigation))
            .where(*conditions)
            .order_by(order_col)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        items = (await session.execute(query_stmt)).scalars().all()
        return list(items), int(total_count)

    async def update_case(
        self,
        session: AsyncSession,
        case_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        assignee: Optional[str] = None,
        analyst_notes: Optional[str] = None,
    ) -> Optional[Case]:
        """Update fields on an existing case."""
        case = await self.get_case_by_id(session, case_id)
        if not case:
            return None

        if title is not None:
            case.title = title.strip()
        if description is not None:
            case.description = description.strip()
        if status is not None:
            new_status = status.lower()
            if new_status == "closed" and case.status != "closed":
                case.closed_at = utc_now()
            elif new_status != "closed" and case.status == "closed":
                case.closed_at = None
            case.status = new_status
        if priority is not None:
            case.priority = priority.lower()
        if assignee is not None:
            case.assignee = assignee.strip() if assignee else None
        if analyst_notes is not None:
            case.analyst_notes = analyst_notes.strip() if analyst_notes else None

        case.updated_at = utc_now()
        await session.flush()
        return case


    async def delete_case(
        self,
        session: AsyncSession,
        case_id: str,
    ) -> bool:
        """Soft-delete a case."""
        case = await self.get_case_by_id(session, case_id)
        if not case:
            return False

        case.deleted_at = utc_now()
        await session.flush()
        return True
