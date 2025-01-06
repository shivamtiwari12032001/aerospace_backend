from django.urls import path
from .import views


urlpatterns = [
    path('users', views.users_list.as_view(), name='user_list'),
    path('user/<str:uuid>', views.user_details.as_view(), name='user_details'),
    path('login', views.login.as_view(), name='login'),
    path('signup', views.signup.as_view(), name='signup'),
    path('send-verification-email', views.send_verification_email.as_view(),
         name='send_verification_email'),
    path('verify-email',
         views.verify_email.as_view(), name='verify_email'),
    path('send-forgot-pass-email',
         views.send_forgot_pass_email.as_view(), name='send_forgot_pass_email'),
    path('change-pass',
         views.change_password.as_view(), name='change_password'),
]
