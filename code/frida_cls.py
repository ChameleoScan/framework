from typing import Self, Dict, List, Union
import frida
import logging

# Configure logging
logger = logging.getLogger(__name__)

class iOSFridaClient:
    def __init__(self, hostname, port=27042):
        self.hostname = hostname
        self.port = port
        self.device = None
        self.session = None

    def connect(self):
        """Connect to the iOS device using Frida."""
        try:
            self.device = frida.get_device_manager().add_remote_device(f"{self.hostname}:{self.port}")
            logger.info("Frida connection established with the device.")
        except Exception as e:
            logger.error(f"Failed to connect to Frida on {self.hostname}:{self.port}: {e}")
            raise e
    
    def clone(self) -> Self:
        """Clone the current instance for another connection."""
        return iOSFridaClient(hostname=self.hostname, port=self.port)

    def disconnect(self):
        """Disconnect from the Frida device."""
        # Frida automatically handles disconnection when objects are deleted
        self.device = None
        logger.info("Frida connection closed.")
    
    def list_applications(self) -> List[Dict]:
        """Retrieve a list of installed applications on the iOS device."""
        if self.device:
            try:
                applications = self.device.enumerate_applications()
                app_list = [{"name": a.name, "identifier": a.identifier} for a in applications]
                logger.debug(f"Retrieved {len(app_list)} applications.")
                return app_list
            except Exception as e:
                logger.error(f"Failed to retrieve applications: {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)
    
    def get_name_by_identifier(self, identifier: str, app_list: List|None = None) -> str:
        """Retrieve the name of an application by its bundle identifier."""
        app_list = app_list if app_list is not None else self.list_applications()
        for app in app_list:
            if app["identifier"] == identifier:
                return app["name"]
        return None
    
    def get_identifier_by_name(self, name: str, app_list: List|None = None) -> str:
        """Retrieve the bundle identifier of an application by its name."""
        app_list = app_list if app_list is not None else self.list_applications()
        for app in app_list:
            if app["name"] == name:
                return app["identifier"]
        return None

    def list_processes(self) -> List[Dict]:
        """Retrieve a list of running processes on the iOS device."""
        if self.device:
            try:
                processes = self.device.enumerate_processes()
                process_list = [{"pid": p.pid, "name": p.name} for p in processes]
                app_list = self.list_applications()
                for p in process_list:
                    if (ident := self.get_identifier_by_name(p["name"], app_list)) is not None:
                        p["identifier"] = ident
                logger.debug(f"Retrieved {len(process_list)} processes.")
                return process_list
            except Exception as e:
                logger.error(f"Failed to retrieve processes: {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)
    
    def kill_process(self, process: Union[int, str]):
        """Kill a process by its name or PID."""
        if self.device:
            try:
                self.device.kill(process)
                logger.debug(f"Killed process with {process}.")
            except Exception as e:
                logger.error(f"Failed to kill process with {process}: {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)
    
    def spawn_and_attach(self, process: str) -> int:
        """Spawn a new process and attach to it, returning the PID. (need manual resume())"""
        if self.device:
            try:
                pid = self.device.spawn([process])
                self.session = self.device.attach(pid)
                logger.debug(f"Spawned and attached to process '{process}' with PID {pid}.")
                setattr(self.session, '_spawn_pid', pid)
                return pid
            except Exception as e:
                logger.error(f"Failed to spawn and attach to process '{process}': {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)
    
    def resume_process(self, process: Union[int, str]):
        """Resume a process by its name or PID."""
        if self.device:
            try:
                self.device.resume(process)
                logger.debug(f"Resumed process with {process}.")
            except Exception as e:
                logger.error(f"Failed to resume process with {process}: {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)

    def attach_to_process(self, process: Union[int, str]):
        """Attach to a specific process by name or PID and return the session."""
        if self.device:
            try:
                self.session = self.device.attach(process)
                setattr(self.session, '_spawn_pid', self.session._impl.pid)
                logger.debug(f"Attached to process '{process}'.")
                return self.session
            except Exception as e:
                logger.error(f"Failed to attach to process '{process}': {e}")
                raise e
        else:
            error_message = "Device connection not established."
            logger.error(error_message)
            raise Exception(error_message)

    def detach(self):
        """Detach from the current session if attached."""
        if self.session:
            try:
                self.session.detach()
                logger.debug("Detached from the process.")
            except Exception as e:
                logger.error(f"Failed to detach from process: {e}")
                raise e
        else:
            logger.warning("No active session to detach from.")
    
    def detach_and_kill(self):
        """Detach from the current process and kill it."""
        if self.session:
            try:
                try:
                    pid = getattr(self.session, '_spawn_pid')
                except:
                    pid = self.session._impl.pid  # Get PID from internal session implementation
                self.session.detach()  # Detach first to avoid potential issues 
                if pid in [p.pid for p in self.device.enumerate_processes()]:
                    self.device.kill(pid)  # Kill the process using its PID
                    delattr(self.session, '_spawn_pid')
                logger.debug("Killed process and detached from it.")
            except Exception as e:
                logger.error(f"Failed to kill process and detach: {e}")
                raise e
        else:
            logger.warning("No active session to kill and detach from.")

    def execute_script(self, script_code: str) -> object:
        """Execute a JavaScript script on the attached process."""
        if self.session:
            try:
                script = self.session.create_script(script_code)
                script.load()
                logger.debug("Script loaded and executed.")
                return script
            except Exception as e:
                logger.error(f"Failed to execute script: {e}")
                raise e
        else:
            error_message = "Session not attached to any process."
            logger.error(error_message)
            raise Exception(error_message)
