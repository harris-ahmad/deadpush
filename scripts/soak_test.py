#!/usr/bin/env python3
"""
Multi-repo soak test for deadpush.

Run this script to test guardian across multiple repositories simultaneously.

Usage:
    python scripts/soak_test.py --repos 3 --duration 60 --agents 5
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_cmd(cmd, cwd=None, capture=True):
    """Run command and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd, cwd=cwd, capture_output=capture, text=True, timeout=60
    )
    return result.returncode, result.stdout, result.stderr


def setup_test_repo(base_dir, name):
    """Create a test git repo with some sample code."""
    repo = base_dir / name
    repo.mkdir(parents=True)
    run_cmd(["git", "init"], cwd=repo)
    run_cmd(["git", "config", "user.email", "test@test.com"], cwd=repo)
    run_cmd(["git", "config", "user.name", "Test User"], cwd=repo)

    # Create sample Python files
    (repo / "main.py").write_text("""
def main():
    print("Hello, World!")
    helper()

def helper():
    unused_var = 42  # dead code
    return "done"

class Calculator:
    def add(self, a, b):
        return a + b

    def subtract(self, a, b):
        return a - b

    def dead_method(self):
        return "never called"
""")

    (repo / "utils.py").write_text("""
import os

def get_env(key, default=None):
    return os.environ.get(key, default)

# Hardcoded secret (should be flagged)
API_KEY = "sk-test-1234567890abcdef"

def process_data(data):
    temp_file = "/tmp/temp_data.txt"  # hardcoded temp path
    with open(temp_file, "w") as f:
        f.write(str(data))
    return temp_file
""")

    run_cmd(["git", "add", "."], cwd=repo)
    run_cmd(["git", "commit", "-m", "Initial commit"], cwd=repo)
    return repo


def agent_worker(repo, agent_id, duration, results):
    """Simulate an AI agent writing files."""
    start = time.time()
    writes = 0
    while time.time() - start < duration:
        # Random write operation
        file_type = random.choice(["py", "md", "txt"])
        filename = f"agent_{agent_id}_file_{writes}.{file_type}"
        filepath = repo / filename

        content = f"# Agent {agent_id} write {writes}\n"
        content += f"temp_var_{writes} = {random.randint(1, 1000)}\n"
        if random.random() < 0.1:
            content += 'SECRET = "sk-bad-secret-123"\n'

        try:
            filepath.write_text(content)
            run_cmd(["git", "add", filename], cwd=repo)
            run_cmd(["git", "commit", "-m", f"Agent {agent_id} write {writes}"], cwd=repo)
            writes += 1
        except Exception as e:
            pass

        time.sleep(random.uniform(0.5, 2.0))

    results[agent_id] = writes


def run_soak_test(num_repos, duration, num_agents):
    """Run the soak test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_dir = Path(tmpdir)

        print(f"Setting up {num_repos} test repos...")
        repos = []
        for i in range(num_repos):
            repo = setup_test_repo(base_dir, f"repo_{i}")
            repos.append(repo)
            print(f"  Created repo_{i}")

        # Install deadpush in each repo
        print("\nInstalling deadpush in each repo...")
        for repo in repos:
            run_cmd([sys.executable, "-m", "pip", "install", "-e", "."], cwd=repo)
            run_cmd(["deadpush", "init", "--mode", "default", "--force"], cwd=repo)

        # Start guardian in each repo
        print("\nStarting guardians...")
        guardian_procs = []
        for repo in repos:
            proc = subprocess.Popen(
                ["deadpush", "protect", "--daemon"],
                cwd=repo,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            guardian_procs.append((repo, proc))

        # Wait for guardians to start
        time.sleep(3)

        # Run agent workers
        print(f"\nStarting {num_agents} agents per repo for {duration}s...")
        all_results = {}
        with ThreadPoolExecutor(max_workers=num_repos * num_agents) as executor:
            futures = []
            for repo in repos:
                for agent_id in range(num_agents):
                    futures.append(executor.submit(
                        agent_worker, repo, agent_id, duration, {}
                    ))

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Agent error: {e}")

        # Stop guardians
        print("\nStopping guardians...")
        for repo, proc in guardian_procs:
            run_cmd(["deadpush", "stop"], cwd=repo)
            proc.terminate()

        # Check results
        print("\n=== SOAK TEST RESULTS ===")
        for repo in repos:
            print(f"\n{repo.name}:")
            run_cmd(["deadpush", "status"], cwd=repo)
            run_cmd(["deadpush", "quarantine", "list"], cwd=repo)

    print("\n=== SOAK TEST COMPLETE ===")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deadpush soak test")
    parser.add_argument("--repos", type=int, default=3, help="Number of test repos")
    parser.add_argument("--duration", type=int, default=30, help="Test duration in seconds")
    parser.add_argument("--agents", type=int, default=3, help="Agents per repo")
    args = parser.parse_args()

    run_soak_test(args.repos, args.duration, args.agents)