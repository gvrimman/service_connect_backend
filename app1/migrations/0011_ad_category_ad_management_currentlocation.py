# Generated by Django 5.1.1 on 2024-11-05 04:37

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0010_alter_invoice_service_register_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Ad_category',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('type', models.CharField(choices=[('banner', 'Banner Ad'), ('card', 'Card Ad'), ('pop_up', 'Pop Up Ad')], max_length=50)),
                ('description', models.CharField(max_length=200)),
                ('rate', models.DecimalField(decimal_places=2, max_digits=5)),
                ('currency', models.CharField(default='INR', max_length=10)),
                ('status', models.CharField(choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Active', max_length=20)),
                ('total_views', models.IntegerField(blank=True, null=True)),
                ('total_hits', models.IntegerField(blank=True, null=True)),
                ('image_width', models.IntegerField()),
                ('image_height', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='Ad_Management',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ad_id', models.PositiveIntegerField()),
                ('title', models.CharField(max_length=100)),
                ('description', models.CharField(max_length=200)),
                ('valid_from', models.DateTimeField()),
                ('valid_up_to', models.DateTimeField()),
                ('target_area', models.CharField(choices=[('up_to_5_km', 'Up to 5 km'), ('up_to_10_km', 'Up to 10 km'), ('up_to_15_km', 'Up to 15 km')], default='up_to_5_km', max_length=100)),
                ('total_days', models.IntegerField()),
                ('total_amount', models.DecimalField(decimal_places=2, max_digits=5)),
                ('image', models.ImageField(upload_to='ad_images/')),
                ('ad_category', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ad_category', to='app1.ad_category')),
                ('ad_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ad_user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CurrentLocation',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('country', models.CharField(max_length=100)),
                ('state', models.CharField(max_length=100)),
                ('city', models.CharField(max_length=100)),
                ('address', models.TextField()),
                ('landmark', models.CharField(blank=True, max_length=100, null=True)),
                ('pincode', models.CharField(max_length=20)),
                ('latitude', models.DecimalField(decimal_places=6, max_digits=9)),
                ('longitude', models.DecimalField(decimal_places=6, max_digits=9)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
