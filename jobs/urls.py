from django.urls import path
from .views import JobListView,JobSearchView

urlpatterns = [
    path('jobs-list/', JobListView.as_view(), name='job-list'),
    path('jobs-search/', JobSearchView.as_view(), name='job-search'),
]
