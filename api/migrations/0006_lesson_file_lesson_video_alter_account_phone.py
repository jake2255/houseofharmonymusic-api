# Generated by Django 5.1.1 on 2024-10-19 06:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_merge_0003_account_phone_0004_rename_courses_course'),
    ]

    operations = [
        migrations.AddField(
            model_name='lesson',
            name='file',
            field=models.FileField(blank=True, null=True, upload_to='api/uploads/'),
        ),
        migrations.AddField(
            model_name='lesson',
            name='video',
            field=models.FileField(blank=True, null=True, upload_to='api/uploads/'),
        ),
        migrations.AlterField(
            model_name='account',
            name='phone',
            field=models.TextField(blank=True, null=True),
        ),
    ]
