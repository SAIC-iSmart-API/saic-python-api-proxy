import datetime
import json
import urllib.parse

import httpx
from flask import Flask, request, make_response
from saic_ismart_client_ng.net.crypto import decrypt_request, encrypt_response
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


@app.route('/api.app/v1/', defaults={'path': ''})
@app.route('/api.app/v1/<path:path>', methods=['GET'])
def do_get(path):
    print(request)
    return 'You want GET path: %s' % path


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['POST'])
@app.route('/api.app/v1/<path:path>', methods=['POST'])
async def do_post(path):
    if path == 'oauth/token':
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
            response = cached_tokens[username]
        else:
            password = unquoted[b'password'][0].decode('utf-8')
            login_type = unquoted[b'loginType'][0].decode('utf-8')
            country_code = unquoted[b'countryCode'][0].decode('utf-8') if b'countryCode' in unquoted else ''
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": request.headers['Authorization']
            }
            firebase_device_id = "cqSHOMG1SmK4k-fzAeK6hr:APA91bGtGihOG5SEQ9hPx3Dtr9o9mQguNiKZrQzboa-1C_UBlRZYdFcMmdfLvh9Q_xA8A0dGFIjkMhZbdIXOYnKfHCeWafAfLXOrxBS3N18T4Slr-x9qpV6FHLMhE9s7I6s89k9lU7DD"
            form_body = {
                "grant_type": "password",
                "username": username,
                "password": password,
                "scope": "all",
                "deviceId": f"{firebase_device_id}###europecar",
                "deviceType": "1",  # 2 for huawei
                "loginType": login_type,
                "countryCode": country_code
            }
            client = httpx.AsyncClient(
                event_hooks={
                    "request": [encrypt_httpx_request_wrapper],
                    "response": [decrypt_httpx_response]
                },
            )
            response = await client.post(url=f'{base_uri}{path}', data=form_body, headers=headers)
            if response.is_success:
                response_json = response.json()
                cached_tokens[username] = response_json
                text_content = json.dumps(response_json)
                ts = response.headers['app-send-date']
                their_verification = response.headers['app-verification-string']
                new_content, new_headers = encrypt_response(
                    original_request_url=str(response.url),
                    original_response_headers=response.headers,
                    original_response_content=response.text,
                    response_timestamp_ms=ts,
                    base_uri=base_uri,
                    tenant_id='459771',
                    user_token=''
                )
                response = make_response(new_content)
                response.headers.update(new_headers)
                return response
            else:
                return (response.status_code, response.content)

    return 'You want POST path: %s' % path


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['DELETE'])
@app.route('/api.app/v1/<path:path>', methods=['DELETE'])
def do_delete(path):
    print(request)
    return 'You want GET path: %s' % path


@app.route('/api.app/v1/', defaults={'path': ''}, methods=['PUT'])
@app.route('/api.app/v1/<path:path>', methods=['PUT'])
def do_put(path):
    print(request)
    return 'You want POST path: %s' % path


if __name__ == '__main__':
    app.run()
