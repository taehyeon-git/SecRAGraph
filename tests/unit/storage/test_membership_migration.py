from security_review.storage.models import MemberRow, MemberSessionRow, ScanReportRow


def test_membership_and_nullable_report_owner_are_in_metadata() -> None:
    assert MemberRow.__tablename__ == "members"
    assert MemberSessionRow.__tablename__ == "member_sessions"
    assert ScanReportRow.__table__.c.owner_member_id.nullable
    assert ScanReportRow.__table__.c.owner_member_id.index
    foreign_keys = ScanReportRow.__table__.c.owner_member_id.foreign_keys
    assert [fk.target_fullname for fk in foreign_keys] == ["app.members.user_id"]
    assert MemberRow.__table__.c.username.unique
    assert MemberSessionRow.__table__.c.token_digest.primary_key
    assert next(iter(MemberSessionRow.__table__.c.member_id.foreign_keys)).ondelete == "CASCADE"
