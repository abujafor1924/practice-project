from django.urls import path
from userauth import views as userauth_view

urlpatterns = [
    path('register/', userauth_view.register_view),
    path('verify-email/', userauth_view.verify_email),
    path('login/', userauth_view.login_view),
    path('logout/', userauth_view.logout_view),
    path('forgot-password/', userauth_view.forgot_password),
    path('reset-password-confirm/', userauth_view.reset_password_confirm),
    path('change-password/', userauth_view.change_password),
    
]
