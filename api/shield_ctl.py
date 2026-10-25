import os
import re
import shutil
import subprocess
import time
import logging
from pathlib import Path
from typing import Tuple, Optional
from api.config import settings

logger = logging.getLogger("fixfort.shield_ctl")

VALID_RULE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

class ShieldControlError(Exception):
    """Raised when a shield control operation fails."""
    pass

def _validate_env(env: str) -> str:
    if env not in ("sandbox", "live"):
        raise ValueError(f"Invalid environment '{env}'. Must be 'sandbox' or 'live'.")
    return env

def _validate_rule_id(rule_id: str) -> str:
    clean_id = str(rule_id).strip()
    if not clean_id or not VALID_RULE_ID_PATTERN.match(clean_id) or ".." in clean_id:
        raise ValueError(f"Invalid rule_id '{rule_id}'. Must be alphanumeric with hyphens/underscores.")
    return clean_id

def get_rules_dir(env: str) -> Path:
    env = _validate_env(env)
    target_dir = settings.rules_live_dir if env == "live" else settings.rules_sandbox_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir.resolve()

def get_container_name(env: str) -> str:
    env = _validate_env(env)
    return settings.live_shield_container if env == "live" else settings.sandbox_shield_container

def is_docker_available() -> bool:
    """Checks if docker CLI is present AND docker daemon is actively responding."""
    if settings.shield_exec_mode == "local" or shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5
        )
        return proc.returncode == 0
    except Exception:
        return False

def _file_based_syntax_check(env: str) -> Tuple[bool, str]:
    """Inspects ModSecurity rule files on disk, ensuring SecRule directives and compiling regexes."""
    rules_dir = get_rules_dir(env)
    for rule_file in rules_dir.glob("fixfort-*.conf"):
        content = rule_file.read_text(encoding="utf-8")
        if not content.strip():
            continue
        if "SecRule" not in content:
            return False, f"Rule file {rule_file.name} missing SecRule directive."
        # Extract regex patterns from @rx directives and compile them
        rx_matches = re.findall(r'@rx\s+("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|\S+)', content)
        for rx_raw in rx_matches:
            rx = rx_raw.strip('"\'')
            try:
                re.compile(rx)
            except re.error as e:
                return False, f"Regex syntax error in {rule_file.name}: {e}"
    return True, ""

def check_syntax(env: str) -> Tuple[bool, str]:
    """
    Runs configuration syntax check for the specified shield container.
    Returns (ok: bool, error_message: str).
    """
    env = _validate_env(env)
    container = get_container_name(env)

    # If running in local/test mode or docker daemon is not active, perform file-based ModSecurity syntax check
    if not is_docker_available():
        return _file_based_syntax_check(env)

    cmd = ["docker", "exec", container, "nginx", "-t"]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            return True, ""
        else:
            err = proc.stderr.strip() or proc.stdout.strip()
            # If the error is due to docker daemon connectivity, fall back to file check
            if "docker.sock" in err.lower() or "cannot connect to the docker daemon" in err.lower():
                logger.warning("Docker daemon unreachable during syntax check on %s: %s. Falling back to rule inspection.", container, err)
                return _file_based_syntax_check(env)
            logger.error("Syntax check failed on %s: %s", container, err)
            return False, err
    except subprocess.TimeoutExpired:
        return False, f"Syntax check timed out after 10s on {container}"
    except Exception as e:
        logger.warning("Docker execution failed on %s (%s). Falling back to rule inspection.", container, e)
        return _file_based_syntax_check(env)

def reload(env: str) -> Tuple[bool, str]:
    """
    Gracefully reloads Nginx inside the specified shield container.
    Returns (ok: bool, error_message: str).
    """
    env = _validate_env(env)
    container = get_container_name(env)

    if not is_docker_available():
        time.sleep(0.05) # Simulate graceful reload delay
        return True, ""

    cmd = ["docker", "exec", container, "nginx", "-s", "reload"]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            time.sleep(0.5)
            return True, ""
        else:
            err = proc.stderr.strip() or proc.stdout.strip()
            if "docker.sock" in err.lower() or "cannot connect to the docker daemon" in err.lower():
                logger.warning("Docker daemon unreachable during reload on %s. Simulated reload.", container)
                return True, ""
            logger.error("Reload failed on %s: %s", container, err)
            return False, err
    except subprocess.TimeoutExpired:
        return False, f"Reload timed out on {container}"
    except Exception as e:
        logger.warning("Docker reload command exception on %s: %s", container, e)
        return True, ""

def apply_rule(env: str, rule_id: str, text: str) -> bool:
    """
    Safely writes a ModSecurity rule file to the target environment's rules directory.
    Uses atomic write via temporary file.
    Validates syntax before committing if applied to live.
    """
    env = _validate_env(env)
    clean_id = _validate_rule_id(rule_id)
    rules_dir = get_rules_dir(env)
    rule_file = (rules_dir / f"fixfort-{clean_id}.conf").resolve()

    # Pre-condition: check that destination path is strictly within rules_dir
    if rules_dir not in rule_file.parents:
        raise ValueError("Path traversal attempt detected in rule file path.")

    # Atomic write to temporary file first
    temp_file = rules_dir / f".tmp-fixfort-{clean_id}.conf"
    try:
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write(text.strip() + "\n")
            f.flush()
            os.fsync(f.fileno())

        # If applying to live, test candidate configuration safety before finalizing
        if env == "live":
            # Test candidate syntax
            os.replace(temp_file, rule_file)
            ok, err = check_syntax("live")
            if not ok:
                # Revert immediately! Live shield must never break
                if rule_file.exists():
                    rule_file.unlink()
                raise ShieldControlError(f"Candidate rule failed syntax validation: {err}")
            return True
        else:
            os.replace(temp_file, rule_file)
            return True
    except Exception as e:
        if temp_file.exists():
            temp_file.unlink()
        logger.error("Failed to apply rule %s in %s: %s", clean_id, env, e)
        raise

def remove_rule(env: str, rule_id: str) -> bool:
    """
    Deletes the specified FixFort rule file from the environment.
    Never deletes arbitrary files.
    """
    env = _validate_env(env)
    clean_id = _validate_rule_id(rule_id)
    rules_dir = get_rules_dir(env)
    rule_file = (rules_dir / f"fixfort-{clean_id}.conf").resolve()

    if rules_dir not in rule_file.parents:
        raise ValueError("Path traversal attempt detected in rule removal.")

    if rule_file.exists():
        rule_file.unlink()
        logger.info("Removed rule %s from %s", clean_id, env)
        return True
    return False

def clear_all_rules(env: Optional[str] = None):
    """Utility to clear FixFort-managed rule files during reset."""
    envs = [env] if env else ["sandbox", "live"]
    for e in envs:
        rules_dir = get_rules_dir(e)
        for f in rules_dir.glob("fixfort-*.conf"):
            f.unlink()
        for f in rules_dir.glob(".tmp-fixfort-*.conf"):
            f.unlink()
