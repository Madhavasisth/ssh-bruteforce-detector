import tempfile
from toolkit.suspicious_login import detect_suspicious_login


def test_suspicious_login_detection():
    log_content = """Jul 20 10:01:23 server sshd[1234]: Failed password for invalid user admin from 2.2.2.2 port 123 ssh2
Jul 20 10:01:25 server sshd[1234]: Failed password for invalid user admin from 2.2.2.2 port 124 ssh2
Jul 20 10:01:27 server sshd[1234]: Failed password for invalid user admin from 2.2.2.2 port 125 ssh2
Jul 20 10:01:29 server sshd[1234]: Failed password for invalid user admin from 2.2.2.2 port 126 ssh2
Jul 20 10:01:30 server sshd[1234]: Failed password for invalid user admin from 2.2.2.2 port 127 ssh2
Jul 20 10:02:00 server sshd[1234]: Accepted password for user admin from 2.2.2.2 port 130 ssh2
"""

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_log:
        temp_log.write(log_content)
        temp_log.flush()

        alerts = detect_suspicious_login(temp_log.name, threshold=5, time_window=120)

        assert len(alerts) == 1
        assert alerts[0]["attacker_ip"] == "2.2.2.2"
        assert alerts[0]["severity"] == "HIGH"
