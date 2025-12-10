# scanner/nmap_runner.py
import shutil
import subprocess
import threading
from typing import List, Optional, Callable, Tuple

# ------------------------------------------------------
# Safe stderr reader
# ------------------------------------------------------
def _stderr_reader(pipe, cb: Optional[Callable[[str], None]], collector: List[str]):
    """
    Read lines from pipe and append to collector, calling cb for each line.
    IMPORTANT: do NOT close the pipe here — proc.communicate() / Popen owners
    should manage file descriptor lifecycle. Closing here can race and cause
    "Bad file descriptor".
    """
    try:
        for line in pipe:
            if line is None:
                break
            ln = line.rstrip("\n")
            collector.append(ln)
            if cb:
                try:
                    cb(ln)
                except Exception:
                    # do not allow callback exceptions to kill the reader
                    pass
    except Exception:
        # be silent — we do not want to crash the reader thread
        pass
    finally:
        # Do not close pipe here; return and let the parent handle cleanup.
        return


# ------------------------------------------------------
# Command builder
# ------------------------------------------------------
def build_nmap_cmd(target: str, mode: str = "fast", nmap_bin: str = "nmap") -> List[str]:
    if mode == "fast":
        return [
            nmap_bin,
            "-Pn",
            "-T4",
            "-F",
            "--open",
            "--script", "vuln",
            "--host-timeout", "2m",
            "-oX", "-",
            target,
        ]

    if mode == "medium":
        return [
            nmap_bin,
            "-Pn", "-sV",
            "--top-ports", "1000",
            "--open",
            "--script", "vuln",
            "-T4",
            "--host-timeout", "5m",
            "-oX", "-",
            target,
        ]

    return [
        nmap_bin,
        "-Pn", "-sV", "-A", "-p-", "--open",
        "--script", "vuln",
        "-T4",
        "--script-timeout", "60s",
        "--host-timeout", "15m",
        "-oX", "-",
        target,
    ]


# ------------------------------------------------------
# Nmap runnera
# ------------------------------------------------------
def run_nmap_and_capture_xml(
    cmd: List[str],
    stderr_line_cb: Optional[Callable[[str], None]] = None,
    timeout: Optional[int] = None
) -> Tuple[int, str, str]:
    """
    Run an nmap command and return (rc, stdout_text, stderr_tail).

    Implementation notes:
    - Resolve the nmap binary with shutil.which where possible.
    - Start a background thread to read stderr (so UI updates can be emitted live).
    - Avoid using subprocess.communicate() when another thread reads stderr;
      instead wait for process exit (proc.wait()) and read stdout after the
      process has terminated to avoid double-reading the same fd.
    - The stderr_collector keeps lines; the function returns the tail joined.
    """
    stderr_collector: List[str] = []

    # Resolve binary path if possible (reduces surprise when PATH differs)
    try:
        if cmd and isinstance(cmd, list) and len(cmd) > 0:
            resolved = shutil.which(cmd[0])
            if resolved:
                cmd = [resolved] + cmd[1:]
    except Exception:
        # non-fatal; continue with given cmd
        pass

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,               # alias for universal_newlines=True
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )
    except Exception as e:
        return 1, "", f"Failed to start nmap: {e}"

    # Start stderr reader thread (the thread MUST NOT close the pipe)
    reader = threading.Thread(
        target=_stderr_reader,
        args=(proc.stderr, stderr_line_cb, stderr_collector),
        daemon=True
    )
    reader.start()

    # --- Read stdout AFTER process exit to avoid racing with stderr reader ---
    stdout_text = ""
    try:
        if timeout:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # timed out: try to kill gracefully, then forcibly if needed
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        proc.wait(timeout=2)
                    except Exception:
                        # give up waiting
                        pass
        else:
            proc.wait()

        # Now process has exited (or we gave up waiting) — read stdout safely
        try:
            if proc.stdout is not None:
                # read remaining stdout (process has terminated so reading is safe)
                stdout_text = proc.stdout.read()
            else:
                stdout_text = ""
        except Exception as e:
            stdout_text = ""
            stderr_collector.append(f"Exception reading stdout after exit: {e}")

    except Exception as e:
        # Unexpected error while managing the process; try to recover and collect what we can
        try:
            proc.kill()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass
        try:
            if proc.stdout is not None:
                stdout_text = proc.stdout.read()
            else:
                stdout_text = ""
        except Exception:
            stdout_text = ""
        stderr_collector.append(f"Exception managing process: {e}")

    # Give stderr reader a short grace period to finish consuming any final lines
    try:
        reader.join(timeout=5)
    except Exception:
        pass

    rc = proc.returncode if proc.returncode is not None else 1
    stderr_tail = "\n".join(stderr_collector[-500:])  # keep only tail
    return rc, stdout_text or "", stderr_tail
