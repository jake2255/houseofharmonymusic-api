from django.conf import settings
from storages.backends.s3boto3 import S3Boto3Storage

class StaticStorage(S3Boto3Storage):
    location = settings.STATICFILES_LOCATION
    default_acl = "public-read"
    querystring_auth = False

class PublicMediaStorage(S3Boto3Storage):
    location = settings.MEDIAFILES_LOCATION
    default_acl = "public-read"
    file_overwrite = False

class PrivateMediaStorage(S3Boto3Storage):
    location = "private"
    default_acl = "private"
    file_overwrite = False
    custom_domain = False