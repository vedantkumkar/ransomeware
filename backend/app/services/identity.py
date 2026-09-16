"""IdentityResponseService — simulated identity response.

Records account state (suspended, sessions revoked) in the identity_state
table. Executes nothing outside the backend process.
"""

from datetime import datetime, timedelta

from .. import db, timeutil


class IdentityResponseService:

    def suspend(self, conn, incident, *, automated: bool, actor: str,
                ts: datetime | None = None) -> None:
        """Suspend the incident user and revoke sessions (simulated)."""
        now = ts or timeutil.utc_now()
        username = incident["username"] or "unknown-user"
        db.execute(conn, """
            INSERT INTO identity_state (username, hostname, user_status, sessions_revoked, updated_at)
            VALUES (?, ?, 'suspended', 1, ?)
            ON CONFLICT(username) DO UPDATE SET
                user_status = 'suspended',
                sessions_revoked = 1,
                hostname = excluded.hostname,
                updated_at = excluded.updated_at
        """, (username, incident["hostname"], timeutil.iso_z(now)))
        if automated:
            db.append_timeline(conn, incident["id"], ts_dt=now,
                title=f"User {username} suspended",
                description=f"Account {username} disabled pending investigation.",
                type_="action")
            db.append_timeline(conn, incident["id"], ts_dt=now + timedelta(seconds=0.4),
                title="Active sessions revoked",
                description=f"All active sessions for {username} were terminated.",
                type_="action")
        else:
            db.append_timeline(conn, incident["id"], ts_dt=now,
                title=f"User {username} suspended by analyst",
                description=f"Account {username} disabled and sessions revoked by {actor}.",
                type_="action", automated=False)
        db.append_activity(conn, ts_dt=now, event="User Account Suspended", actor=actor,
                           actor_type="automation" if automated else "analyst",
                           target=username,
                           details=f"User suspension simulated for {username} ({incident['id']}).")
