#!/usr/bin/env pluginwrapper3

import json
import os

from box_config import BoxConfigurationError, get_auth_identity
from safeguard.sessions.plugin import AAPlugin, AAResponse
from vault import AccessRequestDenied, Vault, VaultError

class Plugin(AAPlugin):
    # Override the `_extract_mfa_password` method so the
    # `AAPlugin._ask_mfa_password` won't ask for one-time password.
    def _extract_mfa_password(self):
        return "not-supported"

    def set_https_proxy(self):
        # sgaa plugin does not support https proxy
        self.unset_https_proxy()

    def do_authenticate(self):
        if (
            self.connection.key_value_pairs
            and "account" in self.connection.key_value_pairs
            and "asset" in self.connection.key_value_pairs
        ):
            self.session_cookie.setdefault(
                "account", self.connection.key_value_pairs["account"]
            )
            self.session_cookie.setdefault(
                "asset", self.connection.key_value_pairs["asset"]
            )

        self.session_cookie.setdefault("SessionId", self.connection.session_id)

        if self.connection.gateway_user:
            return AAResponse.accept()
        try:
            token = self.connection.key_value_pairs["token"]
            vaultaddress = self.connection.key_value_pairs["vaultaddress"]

        except KeyError as error:
            reason = f"Without {error} authentication is denied"
            self.logger.error(reason)
            return AAResponse.deny(reason=reason)

        vault = Vault.connect_vault(vaultaddress)

        try:
            response = vault.authenticate_token(
                token=token, session_id=self.session_cookie["SessionId"]
            )

        except VaultError as error:
            reason = str(error)
            self.logger.error(reason)
            return AAResponse.deny(reason=reason)

        self.session_cookie["SessionKey"] = response["SessionKey"]
        self.session_cookie["VaultAddress"] = vault.address

        return AAResponse.accept().with_gateway_user(
            response["User"], response["Groups"]
        )
    def do_authorize(self):
        if 'AccountName' not in self.connection.key_value_pairs:
            return AAResponse.need_info("Username on the server: ", "AccountName")
        
        self.session_cookie["WorkflowStatus"] = "token-granted"
        token = self.connection.key_value_pairs.get("token")

        if token is None:
            try:
                (
                    vaultaddress,
                    asset_network_address,
                ) = self._start_sps_initiated_workflow()

            except (
                VaultError,
                AccessRequestDenied,
                BoxConfigurationError,
                VaultConfigurationError,
            ) as error:
                reason = str(error)
                self.logger.error(reason)
                return AAResponse.deny(reason=reason)

        else:
            self.session_cookie["token"] = token

            try:
                vaultaddress = self.connection.key_value_pairs["vaultaddress"]
            except KeyError as error:
                reason = f"Without {error} authorization is denied"
                self.logger.error(reason)
                return AAResponse.deny(reason=reason)

            asset_network_address = (
                self.connection.server_hostname or self.connection.server_ip
            )

        vault = Vault.connect_vault(vaultaddress)
        try:
            vault.authorize_session(
                token=self.session_cookie["token"],
                session_id=self.session_cookie["SessionId"],
                session_key=self.session_cookie["SessionKey"],
                client_ip=self.connection.client_ip,
                client_port=self.connection.client_port,
                server_hostname=asset_network_address,
                server_port=self.connection.server_port,
                server_username=self.connection.key_value_pairs['AccountName'],
                protocol=self.connection.protocol,
            )

        except VaultError as error:
            reason = str(error)
            self.logger.error(reason)
            return AAResponse.deny(reason=reason)
        
        return AAResponse.accept()
    
    def _start_sps_initiated_workflow(self):
        self.logger.info("Start SPS initiated workflow")
        auth_user, auth_provider = get_auth_identity(
            self.connection.protocol,
            self.connection.connection_name,
            self.connection.gateway_username,
            self.connection.gateway_domain,
        )
        self.session_cookie["AuthProvider"] = auth_provider
        self.session_cookie["AuthUser"] = auth_user

        vault = Vault.connect_joined_vault()
        self.session_cookie["VaultAddress"] = vault.address

        assets = vault.get_assets_by_hostname_or_address(
            server_hostname=self.connection.server_hostname,
            server_ip=self.connection.server_ip,
            auth_provider=auth_provider,
            auth_user=auth_user,
            protocol=self.connection.protocol,
        )
        if len(assets) != 1:
            raise VaultConfigurationError(
                "No unique asset found",
                address=self.connection.server_ip,
                hostname=self.connection.server_hostname,
            )

        asset_id = assets[0]["Id"]
        asset_network_address = assets[0]["NetworkAddress"]

        accounts = vault.get_accounts_in_scope_for_asset_by_name(
            asset_id=asset_id,
            account_name=self.connection.key_value_pairs['AccountName'],
            account_domain=self.connection.server_domain,
            auth_provider=auth_provider,
            auth_user=auth_user,
        )

        if len(accounts) != 1:
            raise VaultConfigurationError(
                "No unique account found",
                asset_id=asset_id,
                username=self.connection.server_username,
                domain=self.connection.server_domain,
            )

        account_id = accounts[0]["Id"]
        self.target_server_username = accounts[0]["Name"]
        access_request = vault.create_access_request(
            asset_id=asset_id,
            account_id=account_id,
            auth_provider=auth_provider,
            auth_user=auth_user,
            protocol=self.connection.protocol,
        )
        self.session_cookie["WorkflowStatus"] = "access-requested"
        self.session_cookie["AccessRequestId"] = access_request["Id"]

        state_file = OpenAccessRequestStateFile(self.session_cookie["SessionId"])
        state_file.save(
            {
                "AccessRequestId": access_request["Id"],
                "AuthProvider": auth_provider,
                "AuthUser": auth_user,
                "VaultAddress": vault.address,
            }
        )

        try:
            vault.poll_access_request(
                access_request, auth_provider=auth_provider, auth_user=auth_user
            )

        except AccessRequestDenied:
            state_file.delete()
            self.session_cookie["WorkflowStatus"] = "access-denied"

            raise
        
        state_file.delete()

        token = vault.get_session_token(
            access_request, auth_provider=auth_provider, auth_user=auth_user
        )
        self.session_cookie["WorkflowStatus"] = "session-initialized"

        response = vault.authenticate_token(
            token=token, session_id=self.session_cookie["SessionId"]
        )
        self.session_cookie["SessionKey"] = response["SessionKey"]
        self.session_cookie["token"] = token

        return vault.address, asset_network_address
    
    def do_session_ended(self):
        try:
            session_id = self.session_cookie["SessionId"]
        except KeyError:
            return

        workflow_status = self.session_cookie.get("WorkflowStatus", "zorp-timeout")
        credential_status = self.session_cookie.get("CredentialStatus")

        # In case of RDP multiple proxy session belongs to the user's RDP session.
        # The access request can be closed only if the credentails are fetched.
        # In case of zorp-timeout the access request can be closed because zorp won't
        # call the credentalstore plugin.
        if workflow_status != "zorp-timeout" and credential_status != "fetched":
            return

        # In case of timeout zorp kills the plugin and the cookie and session_cookie
        # will be empty, so we have to read the state file for the session info.
        if workflow_status == "zorp-timeout":
            try:
                state_file = OpenAccessRequestStateFile(session_id)
                session_cookie = state_file.get()

            except FileNotFoundError as error:
                self.logger.error(str(error))
                return

            finally:
                state_file.delete()
        else:
            session_cookie = self.session_cookie

        vault = Vault.connect_vault(session_cookie["VaultAddress"])

        try:
            if workflow_status in {"access-requested", "zorp-timeout"}:
                vault.cancel_access_request(
                    access_request_id=session_cookie["AccessRequestId"],
                    auth_provider=session_cookie["AuthProvider"],
                    auth_user=session_cookie["AuthUser"],
                )

            elif workflow_status == "session-initialized":
                vault.check_in_access_request(
                    access_request_id=session_cookie["AccessRequestId"],
                    auth_provider=session_cookie["AuthProvider"],
                    auth_user=session_cookie["AuthUser"],
                )

            if "SessionKey" in session_cookie:
                vault.close_authentication(
                    session_id=session_id,
                    session_key=session_cookie["SessionKey"],
                    token=session_cookie.get("token", "token"),
                )
            else:
                self.logger.info(
                    "Session key is missing to close authentication; state=%s",
                    workflow_status,
                )

        except VaultError as error:
            self.logger.error(str(error))

        return
    
class VaultConfigurationError(Exception):
    def __init__(self, message, **details):
        if details:
            message += "; " + ", ".join(f"{k}={v}" for k, v in details.items())

        super().__init__(message)

class OpenAccessRequestStateFile:
    def __init__(self, session_id):
        state_dir = os.environ.get("SCB_PLUGIN_STATE_DIRECTORY")
        file_name = session_id.replace("/", "_").replace(":", "_")
        self.path = os.path.join(state_dir, file_name)

    def save(self, content):
        with open(self.path, "w") as state_file:
            json.dump(content, state_file)

    def get(self):
        with open(self.path, "r") as state_file:
            return json.load(state_file)

    def delete(self):
        try:
            os.remove(os.path.join(self.path))
        except FileNotFoundError:
            pass
        