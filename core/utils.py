from django.conf import settings
import boto3

# not needed - urls automatically signed
def generate_signed_url(file_path, expiration=3600):
    print(f"Generating signed URL for file_path: {file_path}")  # Debugging
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME,
    )
    return s3.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': settings.AWS_STORAGE_BUCKET_NAME,
            'Key': file_path,
        },
        ExpiresIn=expiration
    )
