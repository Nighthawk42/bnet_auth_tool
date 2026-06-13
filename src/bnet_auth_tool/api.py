"""Online Battle.net authenticator client.

.. warning::
   These flows depend on Blizzard's identity API, which has changed before and
   may be blocked again. They are **unverified** against the live backend.
   Endpoints are configurable in ``settings.yaml`` so they can be re-mapped
   without code changes. Offline vault/TOTP features do not use this module.
"""

from __future__ import annotations

import json
from typing import Any

import requests

from . import __version__
from .config import ApiConfig
from .errors import AuthenticatorError

# Server error bodies can echo back submitted material; cap what we surface.
_MAX_ERROR_BODY = 200


class BattleNetAuthenticator:
    """Thin client for attach / retrieve authenticator operations."""

    def __init__(self, api: ApiConfig):
        self._api = api
        self._session = requests.Session()
        self._session.headers.update(
            {"User-Agent": f"bnet-auth-tool/{__version__}"}
        )

    # -- internals ---------------------------------------------------------- #
    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: Any | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            response = self._session.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json_payload,
                timeout=self._api.timeout,
            )
            response.raise_for_status()

            if response.status_code == 204 or not response.content:
                return {}
            content_type = response.headers.get("Content-Type", "")
            if "application/json" not in content_type:
                raise AuthenticatorError(
                    f"Unexpected content type '{content_type}' from {url}."
                )
            return response.json()

        except requests.exceptions.HTTPError as exc:
            raise self._http_error(exc, url) from exc
        except requests.exceptions.RequestException as exc:
            raise AuthenticatorError(f"Request to {url} failed: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AuthenticatorError(f"Could not decode JSON from {url}: {exc}") from exc

    @staticmethod
    def _http_error(exc: requests.exceptions.HTTPError, url: str) -> AuthenticatorError:
        status = exc.response.status_code

        # Blizzard MFA errors come back as {errorCode, message}; surface those
        # rather than the raw body (which may contain submitted secrets).
        blz_detail = ""
        try:
            payload = exc.response.json()
            if isinstance(payload, dict) and (payload.get("errorCode") or payload.get("message")):
                blz_detail = (
                    f" [errorCode={payload.get('errorCode')} "
                    f"message={payload.get('message')}]"
                )
        except (ValueError, json.JSONDecodeError):
            # Only include a short, generic snippet of an opaque body.
            snippet = (exc.response.text or "").strip().replace("\n", " ")[:_MAX_ERROR_BODY]
            if snippet:
                blz_detail = f" (body: {snippet})"

        hint = ""
        if status == 404 and not blz_detail:
            hint = (
                " Hint: route not found — the endpoint version may have changed. "
                "Update api.* in settings.yaml."
            )
        elif status in (401, 403):
            hint = " Hint: authorization failed (token/scope rejected)."

        return AuthenticatorError(f"HTTP {status} from {url}.{blz_detail}{hint}")

    # -- public flows ------------------------------------------------------- #
    def get_bearer_token(self, session_token: str) -> None:
        payload = {
            "client_id": self._api.client_id,
            "grant_type": "client_sso",
            "scope": "auth.authenticator",
            "token": session_token,
        }
        headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
        response = self._request("POST", self._api.sso_url, headers=headers, data=payload)

        access_token = response.get("access_token")
        if not access_token:
            raise AuthenticatorError("Bearer token not found in SSO response.")
        self._session.headers["Authorization"] = f"Bearer {access_token}"

    def attach_authenticator(self) -> dict[str, Any]:
        if "Authorization" not in self._session.headers:
            raise AuthenticatorError("Bearer token not set; call get_bearer_token first.")

        response = self._request(
            "POST", self._api.attach_url, headers={"accept": "application/json"}
        )
        self._reject_healup(response)

        missing = [k for k in ("serial", "restoreCode", "deviceSecret") if k not in response]
        if missing:
            raise AuthenticatorError(f"API response missing keys: {missing}")
        return response

    def retrieve_device_secret(
        self, account_identifier: str, serial: str, restore_code: str
    ) -> dict[str, Any]:
        # v2/device authenticates via accountIdentifier + serial + restoreCode
        # (no bearer token required), mirroring restoreAuthenticator.
        payload = {
            "accountIdentifier": account_identifier.strip(),
            "serial": serial.strip(),
            "restoreCode": restore_code.strip(),
        }
        response = self._request("POST", self._api.device_url, json_payload=payload)
        self._reject_healup(response)

        if "deviceSecret" not in response:
            raise AuthenticatorError("API response missing 'deviceSecret'.")
        return response

    @staticmethod
    def _reject_healup(response: dict[str, Any]) -> None:
        if response.get("requireHealup"):
            raise AuthenticatorError(
                "Server returned requireHealup=true: the account requires a 'heal up' "
                "step before credentials can be issued. The official app handles this "
                "flow; this tool cannot."
            )
