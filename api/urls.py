"""
    URLs will call a views.py function based on the specified path from the request data
    URL specified from the frontend axios function should have one of the paths below
"""

from django.urls import path
from . import views

urlpatterns = [
    path('check_auth/', views.CheckAuthenticationView, name='check_auth'),
    path('csrf/', views.CsrfTokenView, name='csrf_token'),
    path('register/', views.CreateUserView.as_view(), name="create_user"),
    path('login/', views.LoginAccountView.as_view(), name="login"),
    path('logout/', views.LogoutAccountView.as_view(), name="logout"),
    path('account/', views.AccountView.as_view(), name='account'),
    path('course_list/', views.CourseList, name='course_list'),
    path('courses/', views.CoursesView.as_view(), name='courses'),
    path('account_course/<int:course_id>/', views.AccountCourseView.as_view(), name='account_course'),
    path('services_course/<int:course_id>/', views.ServicesCourseView.as_view(), name='service_course'),
    path('lessons/', views.LessonsView.as_view(), name='lessons'),
    path('lesson/<int:lesson_id>/', views.LessonView.as_view(), name='lesson'),
    path('verification/', views.VerificationView.as_view(), name='verification'),
    path('verification/check/', views.VerificationCheckView.as_view(), name='verification_check'),
    path('email_contact/', views.EmailCommunicationView.as_view(), name='email_contact'),
    path('mass_email_contact/', views.MassEmailCommunicationView.as_view(), name='mass_email_contact'),
    path('request_password_reset/', views.RequestPasswordResetView.as_view(), name='request_password_reset'),
    path('request_username_reset/', views.RequestUsernameResetView.as_view(), name='request_username_reset'),
    path('password_reset/<int:user_id>/<str:token>/', views.PasswordResetView.as_view(), name='password_reset'),
    path('username_reset/<int:user_id>/<str:token>/', views.UsernameResetView.as_view(), name='username_reset'),
    path('create_checkout_session/', views.CreateCheckoutSessionView.as_view(), name='create_checkout'),
    path('checkout_webhook/', views.CheckoutWebHookView.as_view(), name='checkout_webhook'),
]
