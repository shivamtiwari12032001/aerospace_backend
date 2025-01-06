from django.http import JsonResponse
import jwt
from django.conf import settings
from su_auth.models import User


class JWTValidationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith('/api/jobs/'):
            return self.get_response(request)

        auth_header = request.headers.get('Authorization', None)

        if not auth_header:
            return JsonResponse(
                {"error": "Authentication credentials were not provided."},
                status=401
            )

        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(
                token,
                settings.SIMPLE_JWT['SIGNING_KEY'],
                algorithms=[settings.SIMPLE_JWT['ALGORITHM']],
            )

            data = payload.get('data', {})
            pk = data.get('pk')
            uuid = data.get('uuid')

            if not pk or not uuid:
                return JsonResponse({"error": "Invalid token payload."}, status=401)

            user = User.objects.filter(pk=pk, uuid=uuid).first()
            if not user:
                return JsonResponse({"error": "User not found."}, status=401)

            
            user.is_active = user.isActive

            
            request.user = user

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired."}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token."}, status=401)
        except KeyError:
            return JsonResponse({"error": "Invalid token payload."}, status=401)

        return self.get_response(request)
