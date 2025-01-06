import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Job
from .serializers import JobSerializer
from django.db.models import Q
import logging

# Set up logger
logger = logging.getLogger(__name__)

class JobListView(APIView):
    def get(self, request, *args, **kwargs):
        jobs = Job.objects.all()

        if jobs.exists():
            job_serializer = JobSerializer(jobs, many=True)
            title = request.query_params.get('title', None)
            print(title,"shfsjdfkdsj")
            if title:
                jobs = Job.objects.filter(Q(title__icontains=title)) 
            else:
                jobs = Job.objects.all()
            job_serializer = JobSerializer(jobs, many=True)
            return Response(job_serializer.data, status=status.HTTP_200_OK)

        external_api_url = "https://remotive.io/api/remote-jobs"
        try:
            response = requests.get(external_api_url)
            response.raise_for_status() 
            
            logger.info(f"API Response: {response.text}")
            
            jobs_data = response.json()
            jobs_list = jobs_data.get("jobs", [])
            
            if not jobs_list:
                return Response({"error": "No jobs found from the external API"}, status=status.HTTP_404_NOT_FOUND)
            
            # Save the fetched jobs to the database
            for job_data in jobs_list:
                job = Job(
                    title=job_data.get("title"),
                    company=job_data.get("company_name"),
                    category=job_data.get("category"),
                    location=job_data.get("candidate_required_location"),
                    description=job_data.get("description", ""),
                    url=job_data.get("url")
                )
                job.save()

            return Response(job_serializer.data, status=status.HTTP_200_OK)

        except requests.RequestException as e:
            logger.error(f"Failed to fetch jobs: {e}")
            return Response(
                {"error": f"Failed to fetch jobs: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return Response(
                {"error": f"Unexpected error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class JobSearchView(APIView):
    def get(self, request, *args, **kwargs):
        title = request.query_params.get('title', None)
        if title is None:
            jobs = Job.objects.all().values('title').distinct()
        else:
            jobs = Job.objects.filter(Q(title__icontains=title)).values( 'title')
        return Response(list(jobs), status=status.HTTP_200_OK)


