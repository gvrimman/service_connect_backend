# Generated by Django 5.1.1 on 2024-10-20 06:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='invoice',
            name='appointment_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
