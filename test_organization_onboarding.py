"""Focused tests for organization provisioning and first-login onboarding."""

import asyncio
import base64
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import BackgroundTasks, HTTPException
from PIL import Image
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import fastapi_mobile_backend_postgresql as api
from database_models import Base, Organization, User


def _database():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _admin(db):
    admin = User(
        username="platformadmin",
        phone_number="10000000000",
        password_hash=api.hash_password("AdminPassword!"),
        is_admin=True,
        admin_role="admin",
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)
    return admin


def _jpeg_base64() -> str:
    image = Image.new("RGB", (8, 8), "blue")
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG")
    return base64.b64encode(buffer.getvalue()).decode()


def test_organization_approval_activation_and_camera_onboarding(tmp_path, monkeypatch):
    db = _database()
    admin = _admin(db)

    async def scenario():
        submission_background = BackgroundTasks()
        submitted = await api.submit_organization_request(
            api.OrganizationRequestCreate(
                organization_name="Acme Ltd",
                contact_name="Ada Admin",
                contact_email="admin@acme.test",
                contact_phone="+2348000000000",
                username="acme-portal",
                password="AcmePortalSecret!",
            ),
            submission_background,
            db,
        )
        assert len(submission_background.tasks) == 1
        approval_background = BackgroundTasks()
        approved = await api.approve_organization_request(
            submitted["request_id"], api.OrganizationRequestDecision(), approval_background, admin, db
        )
        assert len(approval_background.tasks) == 1
        assert "password" not in repr(approved)
        assert approved["organization_account"]["access"] == "invite"

        org_login = await api.organization_account_login(
            api.OrganizationAccountLogin(username="acme-portal", password="AcmePortalSecret!"), db
        )
        credentials = type("Credentials", (), {"credentials": org_login["token"]})()
        viewer = await api.get_organization_viewer(credentials, db)
        empty_roster = await api.get_organization_users_read_only(viewer, db)
        assert empty_roster["users"] == []

        background = BackgroundTasks()
        staff_result = await api.admin_add_organization_staff(
            approved["organization"]["id"],
            api.AdminOrganizationStaffBatch(users=[api.OrganizationRequestedUser(
                    email="alice@acme.test",
                    full_name="Alice Example",
                    phone_number="+2348111111111",
                    department="Engineering",
                )]),
            background,
            admin,
            db,
        )
        assert staff_result["invited_user_count"] == 1
        assert len(background.tasks) == 1

        user = db.query(User).filter(User.email == "alice@acme.test").one()
        assert user.token is None
        assert user.password_hash is None
        invitation_code = background.tasks[0].args[1]

        activated = await api.activate_invitation(
            api.InvitationActivation(invitation_code=invitation_code, token="AliceSecret!"), db
        )
        db.refresh(user)
        assert user.token is None
        assert api.verify_password("AliceSecret!", user.password_hash)
        assert activated["onboarding_required"] is True

        credentials = type("Credentials", (), {"credentials": activated["token"]})()
        onboarding_user = await api.get_onboarding_user(credentials, db)
        monkeypatch.setattr(api, "UPLOAD_DIR", str(tmp_path))
        result = await api.complete_onboarding_profile(
            api.OnboardingProfile(
                job_title="Engineer",
                address="1 Test Street",
                emergency_contact_name="Bob Example",
                emergency_contact_phone="+2348222222222",
                camera_image_base64=_jpeg_base64(),
                captured_at=datetime.now(timezone.utc),
                camera_attestation=True,
            ),
            onboarding_user,
            db,
        )
        assert result["onboarding_required"] is False
        assert (tmp_path / f"user_{user.id}" / "profile_picture.jpg").exists()
        roster = await api.get_organization_users_read_only(viewer, db)
        assert roster["count"] == 1
        assert roster["users"][0]["full_name"] == "Alice Example"
        assert roster["access"] == "invite"

        # The organization's own portal can invite staff to itself, and resend
        # a pending invite - but not to anyone outside the organization.
        portal_background = BackgroundTasks()
        invited = await api.organization_invite_staff(
            api.AdminOrganizationStaffBatch(users=[api.OrganizationRequestedUser(
                email="carol@acme.test", full_name="Carol Example",
                phone_number="+2348333333333", department="Finance",
            )]),
            portal_background, viewer, db,
        )
        assert invited["invited_user_count"] == 1
        carol = db.query(User).filter(User.email == "carol@acme.test").one()
        assert carol.organization_id == viewer.organization_id
        old_hash = carol.invitation_token_hash
        resend_background = BackgroundTasks()
        await api.organization_resend_staff_invite(carol.id, resend_background, viewer, db)
        db.refresh(carol)
        assert carol.invitation_token_hash != old_hash
        assert len(resend_background.tasks) == 1
        # Alice already activated: resending must be refused.
        with pytest.raises(HTTPException) as activated_err:
            await api.organization_resend_staff_invite(user.id, BackgroundTasks(), viewer, db)
        assert activated_err.value.status_code == 409
        # ...so the portal resets her login instead: old credential and every
        # session are gone, and a reset code goes out.
        reset_background = BackgroundTasks()
        await api.organization_reset_staff_login(user.id, reset_background, viewer, db)
        db.refresh(user)
        assert user.password_hash is None
        assert user.invitation_accepted_at is None
        assert user.invitation_token_hash is not None
        assert reset_background.tasks[0].args[2] == "reset"
        assert db.query(api.UserSession).filter(api.UserSession.user_id == user.id).count() == 0

    asyncio.run(scenario())
    db.close()


def test_expired_invitation_and_cross_organization_message_are_rejected():
    db = _database()
    org_a = Organization(name="Org A", slug="org-a", contact_name="A", contact_email="a@test.dev")
    org_b = Organization(name="Org B", slug="org-b", contact_name="B", contact_email="b@test.dev")
    db.add_all([org_a, org_b])
    db.flush()
    code = "expired-invitation-code-that-is-long"
    alice = User(
        username="alice",
        phone_number="11111111111",
        email="alice@test.dev",
        organization_id=org_a.id,
        invitation_token_hash=api._invitation_digest(code),
        invitation_expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        is_active=True,
    )
    bob = User(
        username="bob",
        phone_number="22222222222",
        email="bob@test.dev",
        organization_id=org_b.id,
        is_active=True,
    )
    db.add_all([alice, bob])
    db.commit()

    with pytest.raises(HTTPException) as expired:
        asyncio.run(api.activate_invitation(api.InvitationActivation(invitation_code=code, token="AliceSecret!"), db))
    assert expired.value.status_code == 400

    with pytest.raises(HTTPException) as isolated:
        api.MessageService.send_message_by_username(db, alice.id, bob.username, "ciphertext")
    assert isolated.value.status_code == 404
    db.close()
