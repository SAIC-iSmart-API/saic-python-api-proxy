import datetime
import json
import urllib.parse
from asyncio import Lock
from functools import partial

import httpx
from flask import make_response, request, current_app
from saic_ismart_client_ng.net.crypto import decrypt_request, encrypt_response
from saic_ismart_client_ng.net.httpx import decrypt_httpx_response, encrypt_httpx_request

from default_settings import get_api_uri, get_tenant_id, get_region


class LoginCredentials:
    def __init__(
            self, *,
            username: str,
            url: str,
            response_text: str,
            headers
    ):
        self.__username = username
        self.__url = url
        self.__response_text = response_text
        self.__headers = headers

    @property
    def username(self) -> str:
        return self.__username

    @property
    def response_text(self) -> str:
        return self.__response_text

    @property
    def headers(self):
        return self.__headers

    @property
    def url(self):
        return self.__url


cached_tokens_lock = Lock()
cached_tokens: dict[str, LoginCredentials] = dict()


async def __encrypt_httpx_request_wrapper(
        user_token: str,
        req: httpx.Request
):
    config = current_app.config
    return await encrypt_httpx_request(
        modified_request=req,
        request_timestamp=datetime.datetime.now(),
        base_uri=get_api_uri(config),
        region=get_region(config),
        tenant_id=get_tenant_id(config),
        user_token=user_token
    )


async def proxy_login(*, path: str):
    async with cached_tokens_lock:
        current_app.logger.info("Proxying login flow")
        raw_data = request.get_data(parse_form_data=False).decode('utf-8')
        decrypted = decrypt_request(
            original_request_url=request.url,
            original_request_headers=request.headers,
            original_request_content=raw_data,
            base_uri=request.url.removesuffix(path),
        )
        unquoted = urllib.parse.parse_qs(decrypted)
        username = unquoted[b'username'][0].decode('utf-8')

        if username in cached_tokens:
            return await __use_cached_credentials(
                request_params=unquoted,
                login_credentials=cached_tokens[username],
                path=path
            )
        else:
            return await __do_login_and_cache(
                request_params=unquoted,
                username=username,
                path=path
            )


async def __use_cached_credentials(
        *,
        request_params: dict,
        login_credentials: LoginCredentials,
        path: str
):
    config = current_app.config
    username = login_credentials.username
    current_app.logger.info("Using cached credentials for user %s", username)
    try:
        # Validate token
        decrypting_client = __get_decrypting_client(
            user_token=json.loads(login_credentials.response_text)['data']['access_token']
        )
        result = await decrypting_client.get(
            url='/user/timezone'
        )
        if result.is_success:
            response_url = login_credentials.url
            ts = login_credentials.headers['app-send-date']
            new_content, new_headers = encrypt_response(
                original_request_url=response_url,
                original_response_headers=login_credentials.headers,
                original_response_content=login_credentials.response_text,
                response_timestamp_ms=ts,
                base_uri=get_api_uri(config),
                tenant_id=get_tenant_id(config),
                user_token=''
            )
            response = make_response(new_content)
            generated_headers = dict(new_headers.items())

            # Remove server-side headers so that flask re-generates them
            generated_headers.pop('content-length')

            response.headers.update(generated_headers)
            return response, 200

    except Exception as e:
        cached_tokens.pop(username, None)

    current_app.logger.warning("Credentials for user %s were invalid, generating new ones", username)

    return await __do_login_and_cache(
        request_params=request_params,
        username=username,
        path=path
    )


async def __do_login_and_cache(*, request_params, username, path):
    current_app.logger.info("Logging in as %s", username)
    config = current_app.config
    password = request_params[b'password'][0].decode('utf-8')
    device_id = request_params[b'deviceId'][0].decode('utf-8')
    device_type = request_params[b'deviceType'][0].decode('utf-8')
    scope = request_params[b'scope'][0].decode('utf-8')
    grant_type = request_params[b'grant_type'][0].decode('utf-8')
    login_type = request_params[b'loginType'][0].decode('utf-8')
    country_code = request_params[b'countryCode'][0].decode('utf-8') if b'countryCode' in request_params else ''
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Authorization": request.headers['Authorization']
    }
    form_body = {
        "grant_type": grant_type,
        "username": username,
        "password": password,
        "scope": scope,
        "deviceId": device_id,
        "deviceType": device_type,
        "loginType": login_type,
        "countryCode": country_code
    }
    decrypting_client = __get_decrypting_client()
    api_response = await decrypting_client.post(url=path, data=form_body, headers=headers)
    if api_response.is_success:
        current_app.logger.info("Successfully logged in as %s, caching token and proceeding", username)
        response_url = str(api_response.url)
        cached_tokens[username] = LoginCredentials(
            username=username,
            url=response_url,
            response_text=api_response.text,
            headers=api_response.headers
        )
        ts = api_response.headers['app-send-date']
        new_content, new_headers = encrypt_response(
            original_request_url=response_url,
            original_response_headers=api_response.headers,
            original_response_content=api_response.text,
            response_timestamp_ms=ts,
            base_uri=get_api_uri(config),
            tenant_id=get_tenant_id(config),
            user_token=''
        )
        response = make_response(new_content)
        generated_headers = dict(new_headers.items())

        # Remove server-side headers so that flask re-generates them
        generated_headers.pop('content-length')

        response.headers.update(generated_headers)
        return response, api_response.status_code
    else:
        response = make_response(api_response.text)
        response.headers.update(api_response.headers.items())
        return response, api_response.status_code


def __get_decrypting_client(*, user_token: str = ''):
    return httpx.AsyncClient(
        base_url=get_api_uri(current_app.config),
        event_hooks={
            "request": [partial(__encrypt_httpx_request_wrapper, user_token)],
            "response": [decrypt_httpx_response]
        },
    )


async def passthrough(*, path: str):
    passthrough_client = httpx.AsyncClient()
    headers = dict(request.headers)
    params = request.args
    if request.method in ['POST', 'PUT']:
        content = request.get_data(parse_form_data=False).decode('utf-8')
    else:
        content = None

    # Cleanup headers so that httpx rewrites them with the proper API host
    headers.pop('Host')

    api_response = await passthrough_client.request(
        url=f'{get_api_uri(current_app.config)}{path}',
        method=request.method,
        params=params,
        headers=headers,
        data=content,
    )
    api_response_headers = api_response.headers
    api_response_content = api_response.content
    api_response_code = api_response.status_code
    response = make_response(api_response_content)
    response.headers.update(api_response_headers.items())
    return response, api_response_code
