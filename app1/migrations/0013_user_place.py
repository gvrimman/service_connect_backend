# Generated by Django 5.1.1 on 2024-11-06 06:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app1', '0012_invoice_description_invoice_invoice_document_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='place',
            field=models.CharField(default='mattam', max_length=20),
        ),
    ]