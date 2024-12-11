# Generated by Django 5.1.1 on 2024-11-19 18:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_course_overview_lesson_overview'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='lesson',
            name='file',
        ),
        migrations.AddField(
            model_name='course',
            name='cover_image',
            field=models.ImageField(blank=True, null=True, upload_to='api/upload_images'),
        ),
        migrations.AddField(
            model_name='lesson',
            name='image',
            field=models.ImageField(blank=True, null=True, upload_to='api/upload_images/'),
        ),
        migrations.AlterField(
            model_name='lesson',
            name='video',
            field=models.FileField(blank=True, null=True, upload_to='api/upload_videos/'),
        ),
    ]
