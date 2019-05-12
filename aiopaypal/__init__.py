import os
import sys
import datetime
import base64
import asyncio
import binascii
from logging import getLogger
from multidict import MultiDict

import aiofiles
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientError
from OpenSSL import crypto


__all__ = ["PaypalError", "Paypal"]

_logger = getLogger(__name__)
_logger.setLevel("DEBUG")

SANDBOX_URL = "https://api.sandbox.paypal.com"
LIVE_URL = "https://api.paypal.com"


ROOT_CERT_PATH = "data/DigiCertHighAssuranceEVRootCA.crt.pem"
INTERMEDIATE_CERT_PATH = "data/DigiCertSHA2ExtendedValidationServerCA.crt.pem"
CERT_PATH_CHAIN = [ROOT_CERT_PATH, INTERMEDIATE_CERT_PATH]


def _safe_getitem(dct, *keys):
    for key in keys:
        try:
            dct = dct[key]
        except (KeyError):
            return None
    return dct


class Extensions:
    pass


class PaypalError(Exception):
    pass


class Paypal:
    def __init__(
        self,
        app=None,
        raise_for_status=True,
        logger=None,
        mode=None,
        client_id=None,
        client_secret=None,
        merchant_id=None,
        email=None,
    ):
        global _logger
        self.raise_for_status = raise_for_status

        # paypal configs
        self.mode = (
            mode
            or _safe_getitem(app.config, "SERVICES", "paypal-v1", "creds", "mode")
            or "sandbox"
        )
        self.client_id = client_id or _safe_getitem(
            app.config, "SERVICES", "paypal-v1", "creds", "client_id"
        )
        self.client_secret = client_secret or _safe_getitem(
            app.config, "SERVICES", "paypal-v1", "creds", "client_secret"
        )
        self.base_url = LIVE_URL if self.mode == "live" else SANDBOX_URL
        self.merchant_id = merchant_id or _safe_getitem(
            app.config, "SERVICES", "paypal-v1", "creds", "merchant_id"
        )
        self.email = email or _safe_getitem(
            app.config, "SERVICES", "paypal-v1", "creds", "email"
        )

        if app is not None:
            if not hasattr(app, "exts"):
                app.exts = Extensions()
            app.exts.paypal = self

        # Set logger
        if logger is not None:
            _logger = logger

        # Token response
        self.client_access_token = None
        self.client_expires_in = None
        self.client_expires_at = None
        self.app_id = None
        self.client_scope = None

        # User token
        self.user_access_token = None
        self.user_refresh_token = None
        self.user_expires_at = None
        self.user_expires_in = None
        self.user_scope = None

    # -----------Headers--------------_#

    @property
    def _client_auth_headers(self):
        if not self.client_id or not self.client_secret:
            raise PaypalError("client ID or client secret were not found")
        creds = "{}:{}".format(self.client_id, self.client_secret)
        token = base64.b64encode(creds.encode()).decode().strip("\n").strip("\r")
        return dict(Authorization="Basic {}".format(token))

    @property
    def _client_access_headers(self):
        if self.client_access_token is not None:
            return dict(Authorization="Bearer {}".format(self.client_access_token))
        else:
            raise PaypalError("No client access token")

    @property
    def _user_access_headers(self):
        if self.user_access_token is not None:
            return dict(Authorization="Bearer {}".format(self.user_access_token))
        else:
            raise PaypalError("No user access token")

    # ----------- Request ----------------#
    async def _request(
        self,
        method,
        url,
        base_url=None,
        headers=None,
        data=None,
        json=None,
        auth=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        # Refresh and prep headers
        await self.refresh_access(as_client)
        if headers is None:
            headers = {}
        if as_client is True:
            headers = {**headers, **self._client_access_headers}
        elif as_client is False:
            headers = {**headers, **self._user_access_headers}

        if isinstance(extra_headers, (dict, MultiDict)):
            headers = {**headers, **extra_headers}

        # Prep url
        if add_base is True:
            base_url = base_url or self.base_url
            if url[0] != "/":
                url = "/" + url
            url = base_url + url

        # Send
        async with ClientSession(auth=auth) as sess:
            _logger.info(">>> " + method + " " + str(url))
            async with sess.request(
                method=method, url=url, headers=headers, data=data, json=json
            ) as resp:
                # Resolve JSON
                try:
                    json_resp = await resp.json(content_type=None)
                except Exception as e:
                    _logger.error(str(e))
                    try:
                        json_resp = await resp.text()
                    except Exception as e:
                        _logger.error(str(e))
                        json_resp = {}

                if not json_resp:  # In case it's an empty string or list
                    json_resp = {}

                # Raise for status and log error
                if self.raise_for_status is not False:
                    try:
                        resp.raise_for_status()
                    except ClientError as e:
                        # Debug
                        _logger.error("\n")
                        _logger.error("URL:")
                        _logger.error(str(url))
                        _logger.error("\n")
                        _logger.error("STATUS:")
                        _logger.error(str(resp.status))
                        _logger.error("\n")
                        _logger.error("HEADERS:")
                        _logger.error(str(headers))
                        _logger.error("\n")
                        _logger.error("FULL HEADERS")
                        _logger.error(resp.request_info.headers)
                        _logger.error("\n")
                        _logger.error("REQ JSON")
                        _logger.error(json)
                        _logger.error("\n")
                        _logger.error("REQ DATA")
                        _logger.error(data)
                        _logger.error("\n")
                        _logger.error("JSON:")
                        _logger.error(str(json_resp))
                        _logger.error("\n")
                        raise PaypalError(e)
                    else:
                        return json_resp
                else:
                    return json_resp

    async def request(
        self,
        method,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method=method,
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def get(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="GET",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def post(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Note:

            Always pass a content-type = json if you'll be sending posts requests without a body.
            Otherwise paypal will return a 500 with no details.

        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="POST",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def update(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="PUT",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def delete(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="DELETE",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def patch(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="PATCH",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    async def options(
        self,
        url,
        data=None,
        json=None,
        as_client=True,
        add_base=True,
        extra_headers=None,
    ):
        """
        Arguments:

            url: second part of the url e.g. /v1/payments ...

            as_client (bool): Sends the request as the client
                              (Using client_id + client_secret)
                              for as_user set it to false
                              for as_anon set it to None

        """
        return await self._request(
            method="OPTIONS",
            url=url,
            data=data,
            json=json,
            as_client=as_client,
            add_base=add_base,
            extra_headers=extra_headers,
        )

    # ----------- Auth -------------#

    # ----Helpers
    @property
    def is_client_access_expired(self):
        if self.client_expires_at is not None:
            return datetime.datetime.utcnow() > self.client_expires_at
        else:
            return True

    @property
    def is_user_access_expired(self):
        if self.user_expires_at is not None:
            return datetime.datetime.utcnow() > self.user_expires_at
        else:
            return True

    def _set_client_access_token(self, json_resp):
        self.client_access_token = json_resp["access_token"]
        self.client_expires_in = json_resp["expires_in"] + 60  # account for clock skew
        self.client_expires_at = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.client_expires_in
        )
        self.app_id = json_resp["app_id"]
        self.client_scope = json_resp["scope"]

    def _set_user_access_token(self, json_resp):
        self.user_access_token = json_resp["access_token"]
        self.user_expires_in = json_resp["expires_in"] + 60  # account for clock skew
        self.user_expires_at = datetime.datetime.utcnow() + datetime.timedelta(
            seconds=self.user_expires_in
        )
        self.user_scope = json_resp["scope"]

    # -----Authorize
    async def authorize_client(self):
        resp = await self._request(
            method="POST",
            headers=self._client_auth_headers,
            url="/v1/oauth2/token",
            data=dict(grant_type="client_credentials"),
            as_client=None,
        )
        self._set_client_access_token(resp)

    async def authorize_user(self, grant):
        # TODO
        args = (
            """grant_type=authorization_code
        &response_type=token&
        redirect_uri=urn:ietf:wg:
        oauth:2.0:oob&code="""
            + grant
        )

    # -----Authentication
    async def authorization_uri(self):
        # TODO
        """ https://developer.paypal.com/docs/integration/direct/identity/get-user-consent/ """
        pass

    # ------Refresh
    async def refresh_access(self, as_client=True):
        # Refresh tokens
        if as_client is True:
            if self.is_client_access_expired:
                await self.refresh_client_access()
        if as_client is False:
            if self.is_user_access_expired:
                await self.refresh_user_access()

    async def refresh_client_access(self):
        return await self.authorize_client()

    async def refresh_user_access(self):
        # TODO
        args = "grant_type=refresh_token&refresh_token=" + self.client_refresh_token

    # ----- Openid connect
    # TODO

    # ----- Crypto
    async def verify_from_headers(self, event_body, headers, webhook_id):
        if isinstance(event_body, dict):
            event_body = str(event_body)
        elif isinstance(event_body, bytes):
            event_body = event_body.decode()
        try:
            transmission_id = headers["Paypal-Transmission-Id".lower()]
            timestamp = headers["Paypal-Transmission-Time".lower()]
            actual_sig = headers["Paypal-Transmission-Sig".lower()]
            cert_url = headers["Paypal-Cert-Url".lower()]
            auth_algo = headers["PayPal-Auth-Algo".lower()]
        except KeyError as e:
            raise PaypalError(e)
        return await self.verify(
            transmission_id=transmission_id,
            timestamp=timestamp,
            webhook_id=webhook_id,
            event_body=str(event_body),
            cert_url=cert_url,
            actual_sig=actual_sig,
            auth_algo=auth_algo,
        )

    async def verify(
        self,
        transmission_id,
        timestamp,
        webhook_id,
        event_body,
        cert_url,
        actual_sig,
        auth_algo="sha256",
    ):
        AUTH_ALGO_MAP = {
            "SHA256withRSA": "sha256WithRSAEncryption",
            "SHA1withRSA": "sha1WithRSAEncryption",
        }
        try:
            if auth_algo != "sha256" and auth_algo not in AUTH_ALGO_MAP.values():
                auth_algo = AUTH_ALGO_MAP[auth_algo]
        except KeyError as e:
            _logger.error("Authorization algorithm mapping not found in verify method.")
            raise PaypalError(e)
        cert = await self._get_cert(cert_url)

        verified = await self._verify_certificate(cert) and self._verify_signature(
            transmission_id,
            timestamp,
            webhook_id,
            event_body,
            cert,
            actual_sig,
            auth_algo,
        )
        if verified is not True:
            raise PaypalError("Notification verification status: {}".format(verified))
        return verified
        # PATH = "/v1/no1tifications/webhooks-events/"

    @staticmethod
    async def _get_cert(cert_url):
        """Fetches the paypal certificate used to sign the webhook event payload
        """
        try:
            async with ClientSession() as sess:
                async with sess.get(cert_url) as resp:
                    resp.raise_for_status()
                    text = await resp.text()
                    if not text:
                        raise PaypalError(
                            "Coultn't fetch certificate from {}".format(cert_url)
                        )
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, text)
            return cert
        except ClientError as e:
            raise PaypalError(e)

    async def _verify_certificate(self, cert):
        """Verify that certificate is unexpired, has valid common name and is trustworthy
        """
        if (
            await self._verify_certificate_chain(cert)
            and self._is_common_name_valid(cert)
            and not cert.has_expired()
        ):
            return True
        else:
            raise PaypalError()

    async def _verify_certificate_chain(self, cert):
        """Verify certificate using chain of trust shipped with sdk
        """
        store = await self._get_certificate_store()
        try:
            store_ctx = crypto.X509StoreContext(store, cert)
            store_ctx.verify_certificate()
            return True
        except Exception as e:
            raise PaypalError(e)

    async def _get_certificate_store(self):
        """Returns a certificate store with the trust chain loaded
        """
        store = crypto.X509Store()
        try:
            for cert_path in CERT_PATH_CHAIN:
                full_path = os.path.join(os.path.dirname(__file__), cert_path)
                async with aiofiles.open(full_path) as f:
                    cert_str = await f.read()
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)
                store.add_cert(cert)
            return store
        except Exception as e:
            raise PaypalError(e)

    @staticmethod
    def _is_common_name_valid(cert):
        """Check that the common name in the certificate refers to paypal"""
        if cert.get_subject().commonName.lower().endswith(".paypal.com"):
            return True
        else:
            raise PaypalError("Certificate common name not valid")

    def _verify_signature(
        self,
        transmission_id,
        timestamp,
        webhook_id,
        event_body,
        cert,
        actual_sig,
        auth_algo,
    ):
        """Verify that the webhook payload received is from PayPal,
        unaltered and targeted towards correct recipient
        """
        expected_sig = self._get_expected_sig(
            transmission_id, timestamp, webhook_id, event_body
        )
        try:
            crypto.verify(
                cert,
                base64.b64decode(actual_sig),
                expected_sig.encode("utf-8"),
                auth_algo,
            )
            return True
        except Exception as e:
            raise PaypalError(e)

    @staticmethod
    def _get_expected_sig(transmission_id, timestamp, webhook_id, event_body):
        """Get the input string to generate the HMAC signature
        """
        data = str(binascii.crc32(event_body.encode("utf-8")) & 0xFFFFFFFF)
        expected_sig = transmission_id + "|" + timestamp + "|" + webhook_id + "|" + data
        return expected_sig
