import datetime
import json
import urllib.parse

import httpx
from flask import Flask, request, make_response
from saic_ismart_client_ng.net.crypto import decrypt_request, encrypt_response, encrypt_response_full
from saic_ismart_client_ng.net.httpx import encrypt_httpx_request, decrypt_httpx_response

app = Flask(__name__)

cached_tokens = dict()
base_uri = 'https://gateway-mg-eu.soimt.com/api.app/v1/'


async def encrypt_httpx_request_wrapper(
        req: httpx.Request
):
    return await encrypt_httpx_request(
        modified_request=req,
        request_timestamp=datetime.datetime.now(),
        base_uri=base_uri,
        region='eu',
        tenant_id='459771',
    )


async def passtrough(path):
    passtrough_client = httpx.AsyncClient()
    headers = dict(request.headers)
    params = request.args
    if request.method in ['POST', 'PUT']:
        content = request.get_data(parse_form_data=False).decode('utf-8')
    else:
        content = None
    headers.pop('Host')
    api_response = await passtrough_client.request(
        url=f'{base_uri}{path}',
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


@app.route('/api.app/v1/', defaults={'path': ''})
@app.route('/api.app/v1/<path:path>', methods=['GET'])
async def do_get(path):
    print(f"do_get {path}")
    return await passtrough(path)


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['POST'])
@app.route('/api.app/v1/<path:path>', methods=['POST'])
async def do_post(path):
    print(f"do_post {path}")
    if path == 'oauth/token':
        return await handle_login(path)
    else:
        return await passtrough(path)


async def handle_login(path):
    decrypting_client = httpx.AsyncClient(
        event_hooks={
            "request": [encrypt_httpx_request_wrapper],
            "response": [decrypt_httpx_response]
        },
    )
    raw_data = request.get_data(parse_form_data=False).decode('utf-8')
    decrypted = decrypt_request(
        original_request_url=request.url,
        original_request_headers=request.headers,
        original_request_content=raw_data,
        base_uri=request.url.removesuffix(path),
    )
    unquoted = urllib.parse.parse_qs(decrypted)
    username = unquoted[b'username'][0].decode('utf-8')
    password = unquoted[b'password'][0].decode('utf-8')
    device_id = unquoted[b'deviceId'][0].decode('utf-8')
    device_type = unquoted[b'deviceType'][0].decode('utf-8')
    scope = unquoted[b'scope'][0].decode('utf-8')
    grant_type = unquoted[b'grant_type'][0].decode('utf-8')
    login_type = unquoted[b'loginType'][0].decode('utf-8')
    country_code = unquoted[b'countryCode'][0].decode('utf-8') if b'countryCode' in unquoted else ''
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
    api_response = await decrypting_client.post(url=f'{base_uri}{path}', data=form_body, headers=headers)
    if api_response.is_success:
        cached_tokens[username] = api_response.text
        ts = api_response.headers['app-send-date']
        new_content, new_headers = encrypt_response_full(
            original_request_url=str(api_response.url),
            original_response_headers=api_response.headers,
            original_response_content=api_response.text,
            response_timestamp_ms=ts,
            base_uri=base_uri,
            tenant_id='459771',
            user_token=''
        )
        response = make_response(new_content)
        generated_headers = dict(new_headers.items())
        generated_headers.pop('content-length')
        response.headers.update(generated_headers)
        return response, api_response.status_code
    else:
        response = make_response(api_response.text)
        response.headers.update(api_response.headers.items())
        return response, api_response.status_code


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['DELETE'])
@app.route('/api.app/v1/<path:path>', methods=['DELETE'])
async def do_delete(path):
    print(f"do_delete {path}")
    return await passtrough(path)


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['PUT'])
@app.route('/api.app/v1/<path:path>', methods=['PUT'])
async def do_put(path):
    print(f"do_put {path}")
    return await passtrough(path)


if __name__ == '__main__':
    app.run(host="127.0.0.1", port=8080, debug=True)
