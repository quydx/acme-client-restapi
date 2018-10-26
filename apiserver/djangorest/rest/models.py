from django.db import models

# Create your models here.



class Customer(models.Model):
    email = models.CharField(max_length=255)
    uri = models.CharField(max_length=255)
    key = models.TextField()
    path = models.CharField(max_length=255)
    objects = models.Manager()
    def __str__(self):
        return self.email
     


class Certificate(models.Model):
    domain = models.CharField(max_length=255)
    cert = models.TextField()
    key = models.TextField()
    key_path = models.CharField(max_length=255)
    cert_path = models.CharField(max_length=255)
    
    owner = models.ForeignKey(
        Customer,
        on_delete=models.CASCADE
    )
    valid_in = models.CharField(max_length=255, default='')
    expire_in = models.CharField(max_length=255, default='')
    objects = models.Manager()

    def __str__(self):
        return self.domain
