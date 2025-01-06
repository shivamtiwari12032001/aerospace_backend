from django.shortcuts import render
from .models import User
from .serializers import UserSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .utils import send_verification_email_helper, generate_verification_email_token, decode_jwt
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from quick_tools.utils.encryption_decryption import encrypt_string, decrypt_string
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
import jwt
from datetime import datetime, timedelta
from decouple import config

# Create your views here.


class users_list(APIView):
    def post(self, req):
        serializer = UserSerializer(data=req.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class user_details(APIView):
    def get(self, req, uuid):
        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            return Response({'Error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = UserSerializer(user)
        dataToReturn = {}
        for ele in serializer.data:
            if ele != 'password':
                dataToReturn[ele] = serializer.data[ele]
        return Response(dataToReturn)

    def delete(self, req, uuid):
        try:
            user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            return Response({'Error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def put(self, req, uuid):
        user = User.objects.get(uuid=uuid)
        serializer = UserSerializer(user, data=req.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class signup(APIView):
    def post(self, request):
        is_authenticated_with_email = request.data.get('is_authenticated_with_email', False)
        is_authenticated_with_google = request.data.get('is_authenticated_with_google', False)
        email = request.data.get('email', None)
        password = request.data.get('password', None)
        isUserExist=User.objects.filter(email=email).exists()
        if(is_authenticated_with_google and isUserExist ):
             user = User.objects.get(email=email)
             payload = {
                    'data': {
                        'pk': user.pk,
                        'uuid': str(user.uuid)
                    },
                    'exp': datetime.utcnow() + timedelta(days=7),
                    'iat': datetime.utcnow(),
             }
             token = jwt.encode(payload, "my_secret_key", algorithm='HS256')
             return Response({'message': 'User is loggedIn', 'token': token}, status=status.HTTP_200_OK)

        if is_authenticated_with_email and isUserExist :
            return Response({
                'error': 'User with this email already exists.Go to the login page->'
            }, status=status.HTTP_400_BAD_REQUEST)

        if is_authenticated_with_email and not password:
            return Response({
                'error': 'Password is required when is_authenticated_with_email is true.'
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            payload = {
                    'data': {
                        'pk': user.pk,
                        'uuid': str(user.uuid)
                    },
                    'exp': datetime.utcnow() + timedelta(days=7),
                    'iat': datetime.utcnow(),
            }
            token = jwt.encode(payload, "my_secret_key", algorithm='HS256')
            return Response({'message': 'Successful Signup', 'token': token}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class login(APIView):
    permission_classes = [AllowAny] 
    def post(self, req):
        is_authenticated_with_email = req.data.get('is_authenticated_with_email', False)
        is_authenticated_with_google = req.data.get('is_authenticated_with_google', False)
        email = req.data.get('email', None)
        password = req.data.get('password', None)
        if not email:
            return Response({"error": 'Email is required'}, status=status.HTTP_401_UNAUTHORIZED)
        password = req.data.get('password', None)
        
        print(is_authenticated_with_email, password,"sdkjfksdkjfkj")
        if is_authenticated_with_email and not password :
            return Response({'error': 'password is required'}, status=status.HTTP_401_UNAUTHORIZED)
        elif not password and not is_authenticated_with_google : 
            return Response({'error': 'At least one authentication method must be specified (email or Google).'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'user does not exists'}, status=status.HTTP_401_UNAUTHORIZED)
        
        print("is_authenticated_with_google:", is_authenticated_with_google)
        print("is_authenticated_with_email:", is_authenticated_with_email)
        if user.password is None:
              return Response({'error': 'you logged in with login providers earlier'}, status=status.HTTP_401_UNAUTHORIZED)
        
        is_authenticated_with_email_and_valid_password = is_authenticated_with_email and user.check_password(password)
        is_password_matched = (is_authenticated_with_google and user.is_authenticated_with_google) or is_authenticated_with_email_and_valid_password
        print(is_password_matched,"passwordMatched")
        if is_password_matched:
             payload = {
                    'data': {
                        'pk': user.pk,
                        'uuid': str(user.uuid)
                    },
                    'exp': datetime.utcnow() + timedelta(days=7),
                    'iat': datetime.utcnow(),
             }
             token = jwt.encode(payload, "my_secret_key", algorithm='HS256')
             return Response({'message': 'User is loggedIn', 'token': token}, status=status.HTTP_200_OK)
        else:
             return Response({'error': 'Wrong credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class send_verification_email(APIView):
    def post(self, req):
        email = req.data.get('email', None)
        if not email:
            return Response({'error': 'email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_400_BAD_REQUEST)
        encryptedUserId = encrypt_string(str(user.uuid))
        token = generate_verification_email_token(encryptedUserId)
        redirectUrl = f'/auth/ve/verify-email?vt={token}'
        print(token)
        send_verification_email_helper(email, redirectUrl)
        return Response({'message': 'Verification email sent'}, status=status.HTTP_200_OK)


class verify_email(APIView):
    def get(self, req):
        token = req.query_params.get('vt', None)
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check token
        try:
            decodedTokenValues = decode_jwt(token)
        except:
            return Response({'error': 'Token is not ok'}, status=status.HTTP_401_UNAUTHORIZED)

        userId = decodedTokenValues.get('userId', None)
        if not userId:
            return Response({'error': 'Token is tempered!'}, status=status.HTTP_401_UNAUTHORIZED)

        decryptedUserId = decrypt_string(userId)

        try:
            user = User.objects.get(uuid=decryptedUserId)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Here i want to update a key in User model
        user.isEmailVerified = True
        user.save()
        return Response(status=status.HTTP_200_OK)


class send_forgot_pass_email(APIView):
    def post(self, req):
        email = req.data.get('email', None)
        if not email:
            return Response({'error': 'email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Email not found'}, status=status.HTTP_404_NOT_FOUND)
        encryptedUserId = encrypt_string(user.uuid)
        token = generate_verification_email_token(encryptedUserId)
        redirectUrl = f'/auth/fp/change-password?vt={token}'
        print(token)
        send_verification_email_helper(email, redirectUrl)
        return Response({'message': 'Verification email sent'}, status=status.HTTP_200_OK)


class change_password(APIView):
    def post(self, req):
        token = req.data.get('token', None)
        if not token:
            return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)
        new_password = req.data.get('new_password', None)
        if not new_password:
            return Response({'error': 'new_password is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Check token
        try:
            decodedTokenValues = decode_jwt(token)
        except:
            return Response({'error': 'Token is not ok'}, status=status.HTTP_401_UNAUTHORIZED)

        userId = decodedTokenValues.get('userId', None)
        if not userId:
            return Response({'error': 'Token is tempered!'}, status=status.HTTP_401_UNAUTHORIZED)

        decryptedUserId = decrypt_string(userId)

        try:
            user = User.objects.get(uuid=decryptedUserId)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_401_UNAUTHORIZED)

        user.set_password(new_password)
        user.save()
        return Response({'message': 'New Password has been set'}, status=status.HTTP_200_OK)
