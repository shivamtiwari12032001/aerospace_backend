# Generated by Django 4.2.14 on 2024-08-03 05:37

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('uuid', models.UUIDField(default=uuid.uuid4, editable=False)),
                ('firstName', models.CharField(max_length=50)),
                ('lastName', models.CharField(max_length=50)),
                ('email', models.EmailField(max_length=50, unique=True)),
                ('image_url', models.URLField(blank=True, max_length=100, null=True)),
                ('isActive', models.BooleanField(default=True)),
                ('isEmailVerified', models.BooleanField(default=False)),
                ('loginProvider', models.CharField(choices=[('google', 'GOOGLE'), ('facebook', 'FACEBOOK'), ('github', 'GITHUB'), ('withcredentials', 'WITHCREDENTIALS')])),
            ],
        ),
    ]