from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from accounts import views

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="auth_register"),
    path("login/", views.LoginView.as_view(), name="auth_login"),
    path("verify-totp/", views.TOTPLoginVerifyView.as_view(), name="auth_verify_totp"),
    path("totp/enroll/", views.TOTPEnrollView.as_view(), name="totp_enroll"),
    path("totp/verify-enrollment/", views.TOTPVerifyEnrollmentView.as_view(), name="totp_verify_enrollment"),
    path("refresh/", TokenRefreshView.as_view(), name="auth_refresh"),
    path("logout/", views.LogoutView.as_view(), name="auth_logout"),
    path("me/", views.CurrentUserView.as_view(), name="auth_me"),
]

# ###-------------------------- Face Recognition - GRD --------------------------###


# urlpatterns.extend([
#     path("register-face/", views.RegisterFaceView.as_view(), name="register-face"),
#     path("verify-face/", views.VerifyFaceView.as_view(), name="verify-face"),
# ])