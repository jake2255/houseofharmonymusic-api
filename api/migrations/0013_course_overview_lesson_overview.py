# Generated by Django 5.1.1 on 2024-11-15 04:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_verification'),
    ]

    operations = [
        migrations.AddField(
            model_name='course',
            name='overview',
            field=models.TextField(default='this is the overview'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='lesson',
            name='overview',
            field=models.TextField(default='exit'),
            preserve_default=False,
        ),
    ]