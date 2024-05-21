import logging
import re

# box_configuration has to be imported before box_config to avoid circular import
# pylint: disable=unused-import
from safeguard.sessions.plugin.box_configuration import BoxConfiguration
from safeguard.sessions.plugin_impl.box_config import BoxConfig

logger = logging.getLogger(__name__)

def get_auth_identity(protocol, connection_name, gateway_username, gateway_domain):
    box_config = BoxConfig()
    connection_policy = _select_connection_policy(box_config, protocol, connection_name)

    if protocol == "rdp":
        rdg = connection_policy["body"]["remote_desktop_gateway"]
        if not rdg["enabled"]:
            raise BoxConfigurationError(
                "No Remote Desktop Gateway is configured for connection",
                connection_name=connection_name,
            )
        if rdg["local_authentication"]["selection"] == "local_user_database":
            return gateway_username, "local"
        else:
            return gateway_username, gateway_domain

    else:
        policies = connection_policy["body"]["policies"]
        auth_policy_ref = policies["authentication_policy"]["meta"]["href"]

        logger.info("GET request to localrest; url=%s", auth_policy_ref)
        auth_policy = box_config.query(auth_policy_ref)
        auth_backend = auth_policy["body"]["backend"]["selection"]
        auth_gateway_methods = None
        if auth_policy["body"].get("gateway_methods", False):
             auth_gateway_methods = auth_policy["body"]["gateway_methods"].get("kerberos",False)
        if (
            auth_gateway_methods
            and "@" in gateway_username
        ):
            return gateway_username.split("@", 1)

        elif auth_backend == "local":
            return gateway_username, "local"

        elif auth_backend == "ldap":
            ldap_server_ref = policies["ldap_server"]["meta"]["href"]
            logger.info("GET request to localrest; url=%s", ldap_server_ref)
            ldap_server = box_config.query(ldap_server_ref)
            user_base_dn = ldap_server["body"]["user_base_dn"]

            return gateway_username, _conv_bind_dn_to_auth_domain(user_base_dn)

    return gateway_username, None

def _select_connection_policy(box_config, protocol, connection_name):
    connections_url = f"/api/configuration/{protocol}/connections"
    logger.info("GET request to localrest; url=%s", connections_url)
    connection_policies = box_config.query(connections_url)["items"]

    for connection_policy in connection_policies:
        if connection_policy["body"]["name"] == connection_name:
            return connection_policy

    raise BoxConfigurationError(
        "Connection policy not found", protocol=protocol, name=connection_name
    )


def _conv_bind_dn_to_auth_domain(bind_dn):
    auth_domain = ".".join(re.findall("dc=([^,]+)", bind_dn, re.IGNORECASE))
    logger.info(
        "Bind dn converted to auth domain; bind_dn=%s, auth_domain=%s",
        bind_dn,
        auth_domain,
    )
    return auth_domain

class BoxConfigurationError(Exception):
    def __init__(self, message, **details):
        if details:
            message += "; " + ", ".join(f"{k}={v}" for k, v in details.items())

        super().__init__(message)


