#!/usr/bin/env python3
"""
App Watchdog - Auto-start/stop discovery when MaynDrive launches/exits

Monitors app lifecycle via ADB and controls the discovery daemon automatically.
Manual Start/Stop buttons still work - this is just smart automation.
"""

import asyncio
import subprocess
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def _adb(args, device_serial: Optional[str] = None, timeout=4):
    """Run ADB command and return (returncode, stdout, stderr)"""
    try:
        cmd = ["adb"]
        if device_serial:
            cmd.extend(["-s", device_serial])
        cmd.extend(args)

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout or "", e.stderr or ""
    except Exception as e:
        logger.warning(f"ADB command failed: {e}")
        return 1, "", str(e)


class AppWatchdog:
    """
    Watches for app start/stop events and triggers callbacks

    Detects when fr.mayndrive.app starts or stops by polling ADB pidof.
    When the app starts, calls on_started(). When it stops, calls on_stopped().
    """

    def __init__(
        self,
        package: str = "fr.mayndrive.app",
        device_serial: str = "emulator-5556",
        poll_interval: float = 1.0,
        on_started: Optional[Callable[[], None]] = None,
        on_stopped: Optional[Callable[[], None]] = None,
        ws_broadcast: Optional[Callable[[dict], None]] = None
    ):
        """
        Args:
            package: Package name to watch
            device_serial: ADB device serial
            poll_interval: How often to check (seconds)
            on_started: Callback when app starts
            on_stopped: Callback when app stops
            ws_broadcast: Function to broadcast events via WebSocket
        """
        self.package = package
        self.device_serial = device_serial
        self.poll_interval = poll_interval
        self.on_started = on_started
        self.on_stopped = on_stopped
        self.ws_broadcast = ws_broadcast

        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_running: Optional[bool] = None

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None):
        """Start the watchdog"""
        if self._task:
            logger.warning("Watchdog already running")
            return

        self._running = True

        if loop is None:
            loop = asyncio.get_event_loop()

        self._task = loop.create_task(self._run())
        logger.info(f"Watchdog started for {self.package}")

    def stop(self):
        """Stop the watchdog"""
        self._running = False

        if self._task:
            self._task.cancel()
            self._task = None

        logger.info("Watchdog stopped")

    async def _run(self):
        """Main watchdog loop"""
        while self._running:
            try:
                is_running = self._is_app_running()

                # Detect state change
                if is_running != self._last_running:
                    self._last_running = is_running

                    if is_running:
                        logger.info(f"📱 {self.package} detected: STARTED")

                        # Broadcast event
                        if self.ws_broadcast:
                            try:
                                self.ws_broadcast({
                                    "type": "watchdog",
                                    "status": "app_started",
                                    "package": self.package
                                })
                            except Exception as e:
                                logger.error(f"Failed to broadcast app_started: {e}")

                        # Trigger callback
                        if self.on_started:
                            try:
                                self.on_started()
                            except Exception as e:
                                logger.error(f"on_started callback failed: {e}")

                    else:
                        logger.info(f"📱 {self.package} detected: STOPPED")

                        # Broadcast event
                        if self.ws_broadcast:
                            try:
                                self.ws_broadcast({
                                    "type": "watchdog",
                                    "status": "app_stopped",
                                    "package": self.package
                                })
                            except Exception as e:
                                logger.error(f"Failed to broadcast app_stopped: {e}")

                        # Trigger callback
                        if self.on_stopped:
                            try:
                                self.on_stopped()
                            except Exception as e:
                                logger.error(f"on_stopped callback failed: {e}")

                await asyncio.sleep(self.poll_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watchdog loop error: {e}", exc_info=True)
                await asyncio.sleep(self.poll_interval)

    def _is_app_running(self) -> bool:
        """Check if the app is currently running"""
        rc, stdout, _ = _adb(
            ["shell", "pidof", self.package],
            device_serial=self.device_serial
        )

        # pidof returns 0 if process found, stdout contains PID
        is_running = rc == 0 and stdout.strip() != ""

        return is_running

    @property
    def is_app_running(self) -> bool:
        """Current app running state"""
        return self._last_running is True
