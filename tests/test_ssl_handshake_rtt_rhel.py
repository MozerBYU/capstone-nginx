import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest


def _run_cmd(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = p.stdout.decode("utf-8", errors="replace")
    stderr = p.stderr.decode("utf-8", errors="replace")
    return p.returncode, stdout, stderr


def _openssl_is_at_least_3_2():
    rc, stdout, _ = _run_cmd(["openssl", "version"])
    if rc != 0:
        return False
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", stdout)
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) >= (3, 2, 0)


def _find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_access_log(path, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
            if lines:
                return lines[-1]
        time.sleep(0.05)
    raise AssertionError("timed out waiting for access log line in {0}".format(path))


@pytest.fixture()
def nginx_ssl_env(tmpdir):
    tmp_path = Path(str(tmpdir))
    repo_root = Path(__file__).resolve().parents[1]
    nginx_bin = repo_root / "objs" / "nginx"

    if not nginx_bin.exists():
        pytest.skip("nginx binary not found at {0}".format(nginx_bin))
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required for this test")
    if shutil.which("curl") is None:
        pytest.skip("curl is required for this test")

    conf_path = tmp_path / "nginx.conf"
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    access_log = tmp_path / "access.log"
    logs_dir = tmp_path / "logs"
    error_log = logs_dir / "error.log"
    port = _find_free_port()

    logs_dir.mkdir(parents=True, exist_ok=True)
    error_log.touch(exist_ok=True)

    rc, _, stderr = _run_cmd(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
        ]
    )
    assert rc == 0, stderr

    conf_path.write_text(
        """
worker_processes  1;

error_log  logs/error.log debug;
pid        logs/nginx.pid;

events {
    worker_connections  128;
}

http {
    log_format rtt '$remote_addr "$request" $status proto="$ssl_protocol" rtt="$ssl_handshake_rtt"';
    access_log  %(access_log)s rtt;

    server {
        listen              127.0.0.1:%(port)s ssl;
        server_name         localhost;

        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_certificate     %(cert_path)s;
        ssl_certificate_key %(key_path)s;

        location / {
            return 200 "ok\\n";
        }
    }
}
"""
        % {
            "access_log": access_log,
            "port": port,
            "cert_path": cert_path,
            "key_path": key_path,
        }
    )

    rc, _, stderr = _run_cmd([str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path), "-t"])
    assert rc == 0, stderr

    rc, _, stderr = _run_cmd([str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path)])
    assert rc == 0, stderr

    try:
        yield {
            "port": port,
            "access_log": access_log,
            "nginx_bin": nginx_bin,
            "prefix": tmp_path,
            "conf": conf_path,
        }
    finally:
        _run_cmd([str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path), "-s", "stop"])


def _extract_rtt_and_proto(log_line):
    m = re.search(r'proto="([^"]+)" rtt="([^"]*)"', log_line)
    assert m, "could not parse ssl fields from access log line: {0}".format(log_line)
    return m.group(1), m.group(2)


def test_ssl_handshake_rtt_tls_below_1_2_rejected_rhel(nginx_ssl_env):
    rc, _, _ = _run_cmd(
        [
            "curl",
            "-k",
            "--http1.1",
            "--tlsv1.1",
            "--tls-max",
            "1.1",
            "https://127.0.0.1:{0}/".format(nginx_ssl_env["port"]),
        ]
    )
    assert rc != 0


def test_ssl_handshake_rtt_empty_when_openssl_pre_3_2_rhel(nginx_ssl_env):
    if _openssl_is_at_least_3_2():
        pytest.skip("OpenSSL >= 3.2; this checks the pre-3.2 fallback only")

    rc, _, stderr = _run_cmd(
        [
            "curl",
            "-k",
            "--http1.1",
            "https://127.0.0.1:{0}/".format(nginx_ssl_env["port"]),
        ]
    )
    assert rc == 0, stderr

    line = _wait_for_access_log(nginx_ssl_env["access_log"])
    _, rtt = _extract_rtt_and_proto(line)
    assert rtt == ""


def test_ssl_handshake_rtt_tls1_2_zero_or_numeric_rhel(nginx_ssl_env):
    rc, _, stderr = _run_cmd(
        [
            "curl",
            "-k",
            "--http1.1",
            "--tlsv1.2",
            "--tls-max",
            "1.2",
            "https://127.0.0.1:{0}/".format(nginx_ssl_env["port"]),
        ]
    )
    assert rc == 0, stderr

    line = _wait_for_access_log(nginx_ssl_env["access_log"])
    proto, rtt = _extract_rtt_and_proto(line)
    assert proto == "TLSv1.2"
    assert rtt == "" or re.fullmatch(r"[0-9]+", rtt)
