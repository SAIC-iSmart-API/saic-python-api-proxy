from flask import Blueprint

from proxy import passthrough, proxy_login

api = Blueprint('api', __name__, url_prefix='/api.app/v1')


@api.route('/', defaults={'path': ''})
@api.route('/<path:path>', methods=['GET'])
async def do_get(path):
    return await passthrough(path=path)


@api.route('/', defaults={'path': ''}, methods=['POST'])
@api.route('/<path:path>', methods=['POST'])
async def do_post(path):
    if path == 'oauth/token':
        return await proxy_login(path=path)
    else:
        return await passthrough(path=path)


@api.route('/', defaults={'path': ''}, methods=['DELETE'])
@api.route('/<path:path>', methods=['DELETE'])
async def do_delete(path):
    return await passthrough(path=path)


@api.route('/', defaults={'path': ''}, methods=['PUT'])
@api.route('/<path:path>', methods=['PUT'])
async def do_put(path):
    return await passthrough(path=path)
