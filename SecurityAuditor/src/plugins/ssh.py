import paramiko
import logging
import asyncio
from typing import Dict, Any
from .base import BasePlugin

# Suppress paramiko logging to avoid clutter
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

class SshPlugin(BasePlugin):
    @property
    def service_name(self) -> str:
        return "ssh"

    async def audit(self, host: str, port: int, **kwargs) -> Dict[str, Any]:
        result = {
            "status": "unknown",
            "risk_level": "none",
            "details": ""
        }
        
        # We need to run paramiko in a thread since it's synchronous
        loop = asyncio.get_event_loop()
        try:
            auth_methods = await loop.run_in_executor(None, self._check_auth, host, port)
            
            if "password" in auth_methods:
                result["status"] = "vulnerable"
                result["risk_level"] = "high"
                result["details"] = f"SSH Server on port {port} allows password authentication, which is vulnerable to brute-force attacks. Recommended: disable password auth and use keys."
            else:
                result["status"] = "secure"
                result["risk_level"] = "low"
                result["details"] = f"SSH on port {port} only accepts: {', '.join(auth_methods)}."
                
        except Exception as e:
            result["status"] = "error"
            result["details"] = f"Failed to audit SSH: {e}"

        return result

    def _check_auth(self, host: str, port: int):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # We connect with a bogus nonexistent user to trigger an auth failure
            # Parameter allowed_types will often list accepted auth methods.
            # Depending on server config, this might just thrown an exception.
            client.connect(host, port=port, username="security_auditor_dummy_user", password="badpassword", timeout=3)
        except paramiko.AuthenticationException as e:
            # Paramiko sometimes includes allowed types in the exception or transport
            transport = client.get_transport()
            if transport:
                try:
                    auth_methods = transport.auth_none("security_auditor_dummy_user")
                    return auth_methods
                except Exception:
                    pass
        except Exception as e:
            pass
        finally:
            client.close()
            
        # Fallback if paramiko couldn't extract auth_none
        return ["unknown"]
