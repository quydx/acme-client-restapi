# Generated by Django 2.0.2 on 2018-10-16 09:15

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Certificate',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain', models.CharField(max_length=255)),
                ('cert', models.TextField()),
                ('key', models.TextField()),
                ('key_path', models.CharField(max_length=255)),
                ('cert_path', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Customer',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(max_length=255)),
                ('uri', models.CharField(max_length=255)),
                ('key', models.CharField(max_length=255)),
                ('path', models.CharField(max_length=255)),
            ],
        ),
        migrations.AddField(
            model_name='certificate',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='rest.Customer'),
        ),
    ]
