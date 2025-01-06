from django.db import models

class Job(models.Model):
    title = models.CharField(max_length=255)
    company = models.CharField(max_length=255)
    category = models.CharField(max_length=255)
    location = models.CharField(max_length=255)
    url = models.URLField(default="") 
    description = models.TextField(default="") 

    def __str__(self):
        return f'{self.title} - {self.company}'
