from flask import Config

SAIC_REST_URI = 'https://gateway-mg-eu.soimt.com/api.app/v1/'
SAIC_REGION = 'eu'
SAIC_TENANT_ID = '459771'


def get_api_uri(config: Config) -> str:
    return config.get('SAIC_REST_URI')


def get_region(config: Config) -> str:
    return config.get('SAIC_REGION')


def get_tenant_id(config: Config) -> str:
    return config.get('SAIC_TENANT_ID')
