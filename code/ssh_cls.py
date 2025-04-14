from typing import Self
import paramiko
import logging

# Configure logging
logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)

class iOSSHClient:
    def __init__(self, hostname, username, password, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port
        self.client = None
        self.sftp = None

    def connect(self):
        """Establish an SSH connection to the device."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.hostname, port=self.port, username=self.username, password=self.password, timeout=10)
            self.client.get_transport().set_keepalive(30)
            logger.info("Connection established.")
        except Exception as e:
            logger.error(f"Failed to connect to {self.hostname}: {e}")
            raise e
    
    def clone(self) -> Self:
        """Clone the current instance for another connection."""
        return iOSSHClient(hostname=self.hostname, username=self.username, password=self.password, port=self.port)

    def disconnect(self):
        """Close the SSH connection."""
        if self.client:
            self.client.close()
            self.client = self.sftp = None
            logger.info("Connection closed.")
        else:
            logger.warning("No active connection to close.")

    def send_command(self, command: str) -> str:
        """Send a command to the device and return the output."""
        if self.client:
            try:
                stdin, stdout, stderr = self.client.exec_command(command)
                output = stdout.read().decode('utf-8')
                logger.debug(f"Command executed: {command}")
                return output
            except Exception as e:
                logger.error(f"Failed to execute command '{command}': {e}")
                raise e
        else:
            error_message = "Connection not established."
            logger.error(error_message)
            raise Exception(error_message)
    
    def get_sftp(self):
        if not self.sftp:
            self.sftp = self.client.open_sftp()
            # Set keepalive to prevent connection timeouts
            transport = self.sftp.get_channel().get_transport()
            transport.set_keepalive(30) # Send keepalive every 30 seconds
        return self.sftp

    def copy_from(self, remote_path: str, local_path: str):
        """Copy a file from the device to the local machine."""
        if self.client:
            try:
                self.get_sftp().get(remote_path, local_path)
                logger.debug(f"File copied from {remote_path} to {local_path}.")
            except Exception as e:
                logger.error(f"Failed to copy file from {remote_path} to {local_path}: {e}")
                raise e
        else:
            error_message = "Connection not established."
            logger.error(error_message)
            raise Exception(error_message)

    def copy_to(self, local_path: str, remote_path: str):
        """Copy a file from the local machine to the device."""
        if self.client:
            try:
                self.get_sftp().put(local_path, remote_path)
                logger.debug(f"File copied from {local_path} to {remote_path}.")
            except Exception as e:
                logger.error(f"Failed to copy file from {local_path} to {remote_path}: {e}")
                raise e
        else:
            error_message = "Connection not established."
            logger.error(error_message)
            raise Exception(error_message)
