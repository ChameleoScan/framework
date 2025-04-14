from typing import Self
from zxtouch.client import zxtouch
from zxtouch.touchtypes import *

# Configure logging
import logging
logger = logging.getLogger(__name__)

from utils import *

class ZXTouchClient(zxtouch):
    def __init__(self, ip):
        self.ip = ip

    def connect(self):
        try:
            super().__init__(self.ip)
            logger.info("Initialized ZXTouchClient.")
        except Exception as e:
            logger.error(f"Failed to connect to {self.ip}: {e}")
            raise e

    def clone(self) -> Self:
        return ZXTouchClient(self.ip)

    def tap(self, x: int, y: int, duration: int = 100):
        """Simulate a tap at the specified coordinates (for duration ms)."""
        try:
            self.touch(TOUCH_DOWN, 1, x, y)
            sleep(duration / 1000)
            self.touch(TOUCH_UP, 1, x, y)
            logger.debug(f"Tapped at ({x}, {y})")
        except Exception as e:
            logger.error(f"Failed to tap at ({x}, {y}): {e}")
            raise e
    
    def input_text(self, text: str):
        assert super().insert_text(text)[0], "Failed to input text"
    
    def hide_keyboard(self):
        assert super().hide_keyboard()[0], "Failed to hide keyboard"
