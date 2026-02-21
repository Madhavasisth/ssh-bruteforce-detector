import tempfile
from toolkit.brute_force import detect_bruteforce


def test_bruteforce_detection():
    log_content = """Jul 20 10:01:23 server sshd[1234]: Failed password for invalid user admin from 1.1.1.1 port 123 ssh2
Jul 20 10:01:25 server sshd[1234]: Failed password for invalid user admin from 1.1.1.1 port 124 ssh2
Jul 20 10:01:27 server sshd[1234]: Failed password for invalid user admin from 1.1.1.1 port 125 ssh2
Jul 20 10:01:29 server sshd[1234]: Failed password for invalid user admin from 1.1.1.1 port 126 ssh2
Jul 20 10:01:30 server sshd[1234]: Failed password for invalid user admin from 1.1.1.1 port 127 ssh2
"""

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_log:
        temp_log.write(log_content)
        temp_log.flush()

        alerts = detect_bruteforce(temp_log.name, threshold=5, time_window=60)

        assert len(alerts) == 1
        assert alerts[0]["attacker_ip"] == "1.1.1.1"
        assert alerts[0]["severity"] == "MEDIUM"
