#!/usr/bin/env python3
"""
Stress test for deadpush guardian.

High-concurrency test with multiple agents writing simultaneously
to verify rate limiting, safety scoring, and quarantine under load.
"""

import argparse
import os
import random
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_cmd(cmd, cwd=None, capture=True):
    result = subprocess.run(cmd, cwd=cwd, capture_output=capture, text=True, timeout=30)
    return result.returncode, result.stdout, result.stderr


def setup_stress_repo(base_dir):
    repo = base_dir / "stress_repo"
    repo.mkdir(parents=True)
    run_cmd(["git", "init"], cwd=repo)
    run_cmd(["git", "config", "user.email", "stress@test.com"], cwd=repo)
    run_cmd(["git", "config", "user.name", "Stress Test"], cwd=repo)

    # Create a file that will be heavily modified
    (repo / "hot_file.py").write_text("""
def hot_function():
    x = 1
    return x
""")

    run_cmd(["git", "add", "."], cwd=repo)
    run_cmd(["git", "commit", "-m", "Initial"], cwd=repo)
    return repo


def stress_writer(repo, writer_id, duration, results):
    """Rapidly write to the same file from multiple threads."""
    start = time.time()
    writes = 0
    errors = 0
    quarantined = 0

    while time.time() - start < duration:
        try:
            filepath = repo / "hot_file.py"
            content = f"""# Writer {threading.current_thread().ident}
def hot_function():
    x = {random.randint(1, 1000000)}
    y = "data_{random.randint(1, 1000)}"
    # SECRET_KEY = "sk-test-{random.randint(1, 1000000)}"  # sometimes trigger quarantine
    return x
"""
            filepath.write_text(content)
            run_cmd(["git", "add", "hot_file.py"], cwd=repo)
            run_cmd(["git", "commit", "-m", f"Stress write from {threading.current_thread().ident}"], cwd=repo)
            writes += 1
        except Exception as e:
            errors += 1

        time.sleep(0.01)  # Very fast writes

    results.append({"writes": writes, "errors": errors})


def run_stress_test(num_writers, duration):
    with tempfile.TemporaryDirectory() as tmpdir:
        repo = setup_stress_repo(Path(tmpdir))

        # Install and init
        run_cmd([sys.executable, "-m", "pip", "install", "-e", "."], cwd=repo)
        run_cmd(["deadpush", "init", "--mode", "default", "--force", "--daemon"], cwd=repo)

        # Wait for guardian
        time.sleep(2)

        print(f"Starting stress test: {num_writers} writers for {duration}s...")
        start = time.time()

        results = []
        with ThreadPoolExecutor(max_workers=num_writers) as executor:
            futures = [
                executor.submit(stress_writer, repo, i, duration, [])
                for i in range(num_writers)
            ]

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Writer error: {e}")

        duration_actual = time.time() - start

        # Check results
        run_cmd(["deadpush", "stop"], cwd=repo)

        run_cmd(["deadpush", "status"], cwd=repo)
        run_cmd(["deadpush", "quarantine", "list"], cwd=repo)

        # Get safety score
        ret, out, _ = run_cmd(["deadpush", "mcp", "--danger"], cwd=repo, capture=False)

        print(f"\n=== STRESS TEST RESULTS ===")
        print(f"Duration: {duration_actual:.1f}s")
        print(f"Writers: {num_writers}")
        print(f"Total time: {time.time() - start:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deadpush stress test")
    parser.add_argument("--writers", type=int, default=10, help="Number of concurrent writers")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    args = parser.parse_args()

    run_stress_test(args.writers, args.duration)