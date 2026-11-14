"""Right-to-be-forgotten blocklist: authors and source URLs that must never be re-ingested."""

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from netra.db.models.base import Base


class BBCorpusBlocklist(Base):
    """One row per blocked author handle or source URL."""

    __tablename__ = "bb_corpus_blocklist"

    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # "author" or "url"
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
