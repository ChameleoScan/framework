from typing import Self, Dict, List, Union

from appium import webdriver
from appium.options.ios import XCUITestOptions

import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("selenium").setLevel(logging.ERROR)

class iOSAppiumClient:
    def __init__(self, local_address: str, driver_address: str = None):
        """
        Initializes the iOSAppiumClient instance.
        :param local_address: Local Appium server address.
        :param driver_address: Optional remote driver address for Appium.
        """
        self.local_address = local_address
        self.driver_address = driver_address
        self.driver = None
        self.capabilities = None
        self.app_ident = None

    def init_connection(self, options: Dict|XCUITestOptions) -> Self:
        """
        Initializes the Appium driver with the provided options.
        :param options: dict capabilities (XCUITestOptions) for configuring the driver.
        :return: Self instance.
        """
        try:
            logger.info("Initializing the Appium driver.")
            address = self.local_address
            if not isinstance(options, XCUITestOptions):
                options = XCUITestOptions().load_capabilities(options)
            self.capabilities = options
            self.driver = webdriver.Remote(command_executor=address, options=options)
            logger.info("Appium driver initialized successfully.")
        except Exception as e:
            logger.error(f"Error initializing Appium driver: {e}")
            raise e
        return self

    def start_session(self, app_ident: str) -> None:
        """
        Starts a new Appium session with the given capabilities.
        :param app_ident: App identifier.
        """
        if not self.driver:
            logger.error("Driver not initialized. Call initialize_driver first.")
            raise RuntimeError("Driver not initialized.")
        try:
            logger.info("Starting Appium session with capabilities.")
            self.driver.start_session(self.capabilities)
            logger.info("Appium session started successfully.")
        except Exception as e:
            logger.error(f"Error starting Appium session: {e}")
            raise e

    def quit_driver(self) -> None:
        """
        Quits the Appium driver and ends the session.
        """
        if self.driver:
            try:
                logger.info("Quitting the Appium driver.")
                self.driver.quit()
                logger.info("Appium driver quit successfully.")
            except Exception as e:
                logger.error(f"Error quitting Appium driver: {e}")
                raise e
        else:
            logger.warning("Driver not initialized. Nothing to quit.")

    def find_element(self, by: str, value: str):
        """
        Finds an element on the app screen.
        :param by: Locator strategy (e.g., 'id', 'xpath', etc.).
        :param value: Locator value.
        :return: Found element.
        """
        if not self.driver:
            logger.error("Driver not initialized. Call initialize_driver first.")
            raise RuntimeError("Driver not initialized.")
        try:
            logger.debug(f"Finding element by {by} with value '{value}'.")
            element = self.driver.find_element(by, value)
            logger.debug("Element found successfully.")
            return element
        except Exception as e:
            logger.error(f"Error finding element: {e}")
            raise e

    def click_element(self, by: str, value: str) -> None:
        """
        Clicks an element on the app screen.
        :param by: Locator strategy (e.g., 'id', 'xpath', etc.).
        :param value: Locator value.
        """
        element = self.find_element(by, value)
        try:
            logger.debug("Clicking element.")
            element.click()
            logger.debug("Element clicked successfully.")
        except Exception as e:
            logger.error(f"Error clicking element: {e}")
            raise e

    def send_keys(self, by: str, value: str, keys: str) -> None:
        """
        Sends keys to an element on the app screen.
        :param by: Locator strategy (e.g., 'id', 'xpath', etc.).
        :param value: Locator value.
        :param keys: Keys to send.
        """
        element = self.find_element(by, value)
        try:
            logger.info(f"Sending keys '{keys}' to element.")
            element.send_keys(keys)
            logger.info("Keys sent successfully.")
        except Exception as e:
            logger.error(f"Error sending keys to element: {e}")
            raise e

    def get_page_source(self) -> str:
        """
        Returns the current page source being shown by the app.
        :return: Current page source as a string.
        """
        if not self.driver:
            logger.error("Driver not initialized. Call initialize_driver first.")
            raise RuntimeError("Driver not initialized.")
        try:
            source = self.driver.page_source
            return source
        except Exception as e:
            logger.error(f"Error getting current page source: {e}")
            raise e
    
    def auto_accept_alerts(self, auto_accept: bool) -> None:
        """
        Auto accept alerts.
        """
        self.driver.update_settings({'autoAcceptAlerts': auto_accept})
    
    def bring_to_foreground(self) -> None:
        """
        Bring the app to foreground.
        """
        self.driver.activate_app(self.app_ident)
    
    def get_current_activity(self) -> str:
        """
        Get the current activity of the app.
        """
        return self.driver.current_activity

    @DeprecationWarning
    def take_screenshot(self, file_path: str) -> None:
        """
        Takes a screenshot of the current app screen.
        :param file_path: Path to save the screenshot.
        """
        if not self.driver:
            logger.error("Driver not initialized. Call initialize_driver first.")
            raise RuntimeError("Driver not initialized.")
        try:
            logger.debug(f"Taking screenshot and saving to '{file_path}'.")
            self.driver.save_screenshot(file_path)
            logger.debug("Screenshot saved successfully.")
        except Exception as e:
            logger.error(f"Error taking screenshot: {e}")
            raise e
        

