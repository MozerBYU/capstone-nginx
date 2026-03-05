import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest


def _openssl_is_at_least_3_2() -> bool:
    p = subprocess.run(["openssl", "version"], capture_output=True, text=True)
    if p.returncode != 0:
        return False
    m = re.search(r"OpenSSL\s+(\d+)\.(\d+)\.(\d+)", p.stdout)
    if not m:
        return False
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) >= (3, 2, 0)


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_for_access_log(path: Path, timeout: float = 2.0) -> str:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            lines = [line.strip() for line in path.read_text().splitlines() if line.strip()]
            if lines:
                return lines[-1]
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for access log line in {path}")


@pytest.fixture()
def nginx_ssl_env(tmp_path):
    repo_root = Path(__file__).resolve().parents[1]
    nginx_bin = repo_root / "objs" / "nginx"

    if not nginx_bin.exists():
        pytest.skip(f"nginx binary not found at {nginx_bin}")
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
    #os.chmod(tmp_path, 0o755)
    #os.chmod(logs_dir, 0o777)
    #os.chmod(error_log, 0o666)

    gen_cert = subprocess.run(
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
        ],
        capture_output=True,
        text=True,
    )
    assert gen_cert.returncode == 0, gen_cert.stderr

    conf_path.write_text(
        f"""
worker_processes  1;

error_log  logs/error.log debug;
pid        logs/nginx.pid;

events {{
    worker_connections  128;
}}

http {{
    log_format rtt '$remote_addr "$request" $status proto="$ssl_protocol" rtt="$ssl_handshake_rtt"';
    access_log  {access_log} rtt;

    server {{
        listen              127.0.0.1:{port} ssl;
        server_name         localhost;

        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_certificate     {cert_path};
        ssl_certificate_key {key_path};

        location / {{
            return 200 "ok\\n";
        }}
    }}
}}
""".strip()
        + "\n"
    )

    test_conf = subprocess.run(
        [str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path), "-t"],
        capture_output=True,
        text=True,
    )
    assert test_conf.returncode == 0, test_conf.stderr

    started = subprocess.run(
        [str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path)],
        capture_output=True,
        text=True,
    )
    assert started.returncode == 0, started.stderr

    try:
        yield {
            "port": port,
            "access_log": access_log,
            "nginx_bin": nginx_bin,
            "prefix": tmp_path,
            "conf": conf_path,
        }
    finally:
        subprocess.run(
            [str(nginx_bin), "-p", str(tmp_path), "-c", str(conf_path), "-s", "stop"],
            capture_output=True,
            text=True,
        )


def _extract_rtt_and_proto(log_line: str):
    m = re.search(r'proto="([^"]+)" rtt="([^"]*)"', log_line)
    assert m, f"could not parse ssl fields from access log line: {log_line}"
    return m.group(1), m.group(2)


def test_ssl_handshake_rtt_tls_below_1_2_rejected(nginx_ssl_env):
    p = subprocess.run(
        [
            "curl",
            "-k",
            "--http1.1",
            "--tlsv1.1",
            "--tls-max",
            "1.1",
            f"https://127.0.0.1:{nginx_ssl_env['port']}/",
        ],
        capture_output=True,
        text=True,
    )
    assert p.returncode != 0


def test_ssl_handshake_rtt_empty_when_openssl_pre_3_2(nginx_ssl_env):
    if _openssl_is_at_least_3_2():
        pytest.skip("OpenSSL >= 3.2; this checks the pre-3.2 fallback only")

    p = subprocess.run(
        [
            "curl",
            "-k",
            "--http1.1",
            f"https://127.0.0.1:{nginx_ssl_env['port']}/",
        ],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 0, p.stderr

    line = _wait_for_access_log(nginx_ssl_env["access_log"])
    _, rtt = _extract_rtt_and_proto(line)
    assert rtt == ""


def test_ssl_handshake_rtt_tls1_2_zero_or_numeric(nginx_ssl_env):
    p = subprocess.run(
        [
            "curl",
            "-k",
            "--http1.1",
            "--tlsv1.2",
            "--tls-max",
            "1.2",
            f"https://127.0.0.1:{nginx_ssl_env['port']}/",
        ],
        capture_output=True,
        text=True,
    )
    assert p.returncode == 0, p.stderr

    line = _wait_for_access_log(nginx_ssl_env["access_log"])
    proto, rtt = _extract_rtt_and_proto(line)
    assert proto == "TLSv1.2"
    assert rtt == "" or re.fullmatch(r"[0-9]+", rtt)
