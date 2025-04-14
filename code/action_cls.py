from abc import ABC, abstractmethod
from typing import List

from gpt_cls import GPTClient, UIView, UserAction, UserActionTypeClick, UserActionTypeCompleted, UserActionTypeInput, UserActionTypeNone, UserActionTypeRestart
from ui_cls import BaseUI

from utils import sleep, rand

import logging
logger = logging.getLogger(__name__)

class BaseAction(ABC):
    @abstractmethod
    def __init__(self, vars):
        pass

    @classmethod
    @abstractmethod
    def create_action(cls, vars):
        pass

    def replace_action(self, vars):
        self.__init__(vars)
        return self

    @staticmethod
    def analyze_action(*args, **kwargs) -> UserAction:
        # Use GPT-4o to analyze the UIView and provide a response
        gpt = GPTClient()
        actions = gpt.analyze_action(*args, **kwargs)
        return actions
    
    @staticmethod
    def _get_ui_slim(ui: UIView) -> str:
        return GPTClient._get_slim_ui(ui)
    
    @staticmethod
    def _get_action_history(action_history: List[str]) -> str:
        return GPTClient._get_action_history(action_history)

    @abstractmethod
    def apply_actions(self, actions: UserAction) -> int|bool:
        pass

class iOSAction(BaseAction):
    def __init__(self, vars):
        self.restart_app, self.zc, self.appium_ui, self.bring_to_foreground, self.gbscript = vars

    @classmethod
    def create_action(cls, vars):
        return cls(vars)

    def tap(self, x, y):
        self.zc.tap(x, y)
    
    def hide_keyboard(self):
        self.bring_to_foreground() # Bring to foreground before calling gbscript (otherwise stuck)
        self.zc.hide_keyboard() # This zxtouch solution also works
        self.gbscript.exports_sync.hidekeyboard() # This frida solution also works
        sleep(rand(0.5, 1)) # make sure the keyboard is hidden
    
    def input_text(self, text: str):
        self.zc.input_text(text)

    def apply_actions(self, actions: UserAction, vid_map: dict, base_ui: BaseUI) -> int|bool:
        effective_actions = 0
        for action in actions.actions:
            match action.action:
                case UserActionTypeClick(type="click", element_id=element_id, times=times):
                    assert action.target_element_id == element_id, f"Target element ID mismatch: {action.target_element_id} != {element_id}"
                    logger.debug(f"Applying action: Click action on element_id={element_id}, {times} time(s).")
                    center = base_ui.get_center(vid_map[element_id])
                    for _ in range(times):
                        self.tap(center['x'], center['y'])
                        sleep(rand(0.1, 0.2))
                    self.hide_keyboard()
                    effective_actions += 1
                case UserActionTypeInput(type="input", element_id=element_id, text=text):
                    assert action.target_element_id == element_id, f"Target element ID mismatch: {action.target_element_id} != {element_id}"
                    logger.debug(f"Applying action: Input action on element_id={element_id} with text='{text}'.")
                    center = base_ui.get_center(vid_map[element_id])
                    self.tap(center['x'], center['y'])
                    sleep(rand(0.5, 1))
                    self.input_text('\b' * 20 + text + '\n')
                    sleep(rand(0.5, 1))
                    self.hide_keyboard()
                    effective_actions += 1
                case UserActionTypeRestart(type="restart"):
                    logger.debug("Applying action: Restart the app.")
                    sleep(2)
                    self.restart_app()
                    effective_actions += 1
                case UserActionTypeCompleted(type="completed"):
                    logger.info("Applying action: The task is already accomplished.")
                    return True
                case UserActionTypeNone(type="none"):
                    logger.debug("Applying action: Skip.")
                case _:
                    raise NotImplementedError(f"Unknown action type: {action}")
        return effective_actions

