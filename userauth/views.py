from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .serializers import *
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
import jwt


# Register
@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message": "Check your email to verify."}, status=201)
    return Response(serializer.errors, status=400)


# Verify Email
@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request):
    token = request.GET.get('token')
    if not token:
        return Response({"error": "Missing token"}, status=400)
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user = User.objects.get(id=payload['user_id'])
        if user.is_active:
            return Response({"message": "Already verified."})
        user.is_active = True
        user.save()
        return Response({"message": "Email verified."})
    except:
        return Response({"error": "Invalid or expired token"}, status=400)


# Login
@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = authenticate(
            username=serializer.validated_data['username'],
            password=serializer.validated_data['password']
        )
        if user is None:
            return Response({"error": "Invalid credentials"}, status=401)
        if not user.is_active:
            return Response({"error": "Verify your email first"}, status=403)

        refresh = RefreshToken.for_user(user)
        return Response({
            "message": "Login successful",
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        })
    return Response(serializer.errors, status=400)


# Logout
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data["refresh"]
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({"message": "Logout successful"}, status=205)
    except Exception as e:
        return Response({"error": str(e)}, status=400)


# Forgot Password
@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    serializer = PasswordResetSerializer(data=request.data)
    if serializer.is_valid():
        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            uid = user.id
            reset_url = f"http://localhost:8000/api/reset-password-confirm/?uid={uid}&token={token}"
            send_mail(
                "Reset your password",
                f"Click to reset: {reset_url}",
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False
            )
            return Response({"message": "Password reset email sent."})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
    return Response(serializer.errors, status=400)


# Reset Confirm
@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_confirm(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    if serializer.is_valid():
        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']
        try:
            user = User.objects.get(id=uid)
            if PasswordResetTokenGenerator().check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password reset successful"})
            else:
                return Response({"error": "Invalid or expired token"}, status=400)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)
    return Response(serializer.errors, status=400)


# Change Password
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    serializer = ChangePasswordSerializer(data=request.data)
    if serializer.is_valid():
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({"error": "Old password is incorrect"}, status=400)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "Password changed successfully"})
    return Response(serializer.errors, status=400)
