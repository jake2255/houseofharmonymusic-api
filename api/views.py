"""
    Views recieves the data from the frontend, performs some logic, 
    and returns data to the frontend
    
    "request" variable contains data received from the frontend
    "request" has: user object, sessionid, method (get, post, etc), URL path, and more

    In settings.py, default permission is set to require a user to be authenticated
    Setting permission to "Allow_Any" will allow a request from non-authenticated user
"""

from .serializers import *
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from .models import Account, Lesson, Course
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import login, logout
from django.middleware.csrf import get_token
from django.http import JsonResponse, FileResponse
import random # For generating verification code
from django.shortcuts import redirect
from django.conf import settings
import stripe
from django.core.mail import send_mail, send_mass_mail, EmailMessage
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.parsers import MultiPartParser
from smtplib import SMTPException
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator, default_token_generator

def CheckAuthenticationView(request):
    """Checks if the requesting user is logged in"""
    if request.user.is_authenticated: # if user has activate session, is true
        return JsonResponse({'authenticated': True}) # JsonResponse is a built-in serializer
    return JsonResponse({'authenticated': False})

@permission_classes([AllowAny])
def CsrfTokenView(request):
    """Create csrf token and send to frontend"""
    csrf_token = get_token(request) # built-in function that creates csrf tokens
    return JsonResponse({'csrfToken': csrf_token})

@permission_classes([AllowAny])
def checkAccountValidity(request):
    return CreateUserSerializer(data=request.data).is_valid()

class CreateUserView(APIView):
    """Register a new user"""
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = CreateUserSerializer(data=request.data) # deserialize registration data
        
        if serializer.is_valid():  # built-in function that validates data
            serializer.save() # saves serialized valid data
            return Response(serializer.data, status=status.HTTP_201_CREATED) # sends response to frontend
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST) # or sends error msg

class LoginAccountView(APIView):
    """Login to user's account"""
    permission_classes = [AllowAny]

    def post(self, request):
        login_serializer = LoginAccountSerializer(data=request.data) # deserialize login data
        
        if login_serializer.is_valid():
            # parse account and user from validated data
            user = login_serializer.validated_data['user']
            account = login_serializer.validated_data['account']

            login(request, user) # built-in function that logs in user and creates session 
            
            # serialize user and account data to send
            user_serializer = UserSerializer(user)
            account_serializer = AccountSerializer(account)

            # check if requesting user is superuser
            user_auth = 'false'
            if user.is_superuser:
                user_auth = 'true'

            response_data = {
                'message': 'Login Successful',
                'user_info': user_serializer.data,
                'account_info': account_serializer.data,
                'user_auth' : user_auth                
            }
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(login_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LogoutAccountView(APIView):
    """Logout user's account"""
    def post(self, request):
        logout(request) # built-in function that logs out user and ends session
        return Response({'message': 'Logged out successfully'}, status=status.HTTP_200_OK)

class AccountView(APIView):
    """Retrieve and update an account"""
    def get(self, request): 
        try:
            account = Account.objects.get(user=request.user) # gets requesting user's account
            serializer = AccountSerializer(account) # serialize user's account
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Account.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request):
        try:
            account = Account.objects.get(user=request.user) # gets requesting user's account
            serializer = AccountSerializer(account, data=request.data, partial=True) # serialize account
            if serializer.is_valid():
                serializer.save() # saves the updated serialized data
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Account.DoesNotExist:
            return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([AllowAny])
def CourseList(request):
    """Return list of all courses"""
    courses = Course.objects.all() # gets all courses
    serializer = CourseSerializer(courses, many=True) # serialize courses
    return Response(serializer.data)

class CoursesView(APIView):
    """Retrieve all courses owned by account or create a course"""
    def get(self, request):
        try:
            account = Account.objects.get(user=request.user) # gets requesting user's account
            courses = account.courses.all() # gets all courses linked to the account
            serializer = CourseSerializer(courses, many=True) # serialize the courses
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Course.DoesNotExist:
            return Response({"error": "Courses not found."}, status=status.HTTP_404_NOT_FOUND)
        
    def post(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized to add courses."}, status=status.HTTP_403_FORBIDDEN)

        course_data = request.data
        lesson_ids = request.data.getlist("lessonIds")
        
        serializer = CourseSerializer(data=course_data)
        if serializer.is_valid():
            course = serializer.save()
            for lesson_id in lesson_ids:
                lesson = Lesson.objects.get(id=lesson_id)
                course.lessons.add(lesson)
            account = Account.objects.get(user=request.user)
            account.courses.add(course)
            return Response({"message": "Course successfully created"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Invalid course data."}, status=status.HTTP_400_BAD_REQUEST)

class AccountCourseView(APIView):
    """Retrieve or delete a course from user's account"""
    def get(self, request, course_id):
        try:
            account = Account.objects.get(user=request.user) # gets requesting user's account
            course = account.courses.get(id=course_id) # gets specified course from account
            course_serializer = CourseSerializer(course) # serialize the course
            lessons = course.lessons.all() # gets all lessons in specified course
            lesson_serializer = LessonPreviewSerializer(lessons, many=True) # serialize lesson preview

            response_data = {
                'message': 'Course retrieved successfully',
                'course': course_serializer.data,
                'lessons_preview': lesson_serializer.data,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Course.DoesNotExist:
            return Response({"error": "Course not found."}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, course_id):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized to delete courses."}, status=status.HTTP_403_FORBIDDEN)
        try:
            course = Course.objects.get(id=course_id)
            lessons = course.lessons.all()
            lessons.delete()
            course.delete()
            return Response({"success": "Course deleted."}, status=status.HTTP_200_OK)
        except Course.DoesNotExist:
            return Response({"error": "Course not found."}, status=status.HTTP_404_NOT_FOUND)

class ServicesCourseView(APIView):
    """Retrieve a course from services page"""
    permission_classes = [AllowAny]

    def get(self, request, course_id):
        try:
            course = Course.objects.get(id=course_id) # gets specified course from all courses
            course_serializer = CourseSerializer(course) # serialize the course
            lessons = course.lessons.all() # gets all lessons in specified course
            lesson_serializer = LessonPreviewSerializer(lessons, many=True) # serialize lesson preview
            owns_course = False

            if request.user.is_authenticated:
                account = Account.objects.get(user=request.user)
                owns_course = account.courses.filter(id=course.id).exists()

            response_data = {
                'message': 'Course retrieved successfully',
                'course': course_serializer.data,
                'lessons_preview': lesson_serializer.data,
                'course_owned': owns_course
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Course.DoesNotExist:
            return Response({"error": "Course not found."}, status=status.HTTP_404_NOT_FOUND)

class LessonsView(APIView):
    """Create, update or delete an individual lesson"""
    def post(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized to add lessons."}, status=status.HTTP_403_FORBIDDEN)

        lessons_data = []
        i = 0

        while True:
            lesson_title = request.data.get(f"lesson_{i}_title")
            if not lesson_title:
                break
            lesson = {
                "title": lesson_title,
                "overview": request.data.get(f"lesson_{i}_overview"),
                "description": request.data.get(f"lesson_{i}_description"),
                "video": request.FILES.get(f"lesson_{i}_video"),
                "image": request.FILES.get(f"lesson_{i}_image"),
            }
            lessons_data.append(lesson)
            i += 1

        serializer = LessonSerializer(data=lessons_data, many=True)
        if serializer.is_valid():
            lessons = serializer.save()
            lesson_ids = []
            for lesson in lessons:
                lesson_ids.append(lesson.id)
            return Response({"message": "Lessons created", "lesson_ids": lesson_ids}, status=status.HTTP_201_CREATED)
        else:
            return Response({"error": "Invalid course data."}, status=status.HTTP_400_BAD_REQUEST)

    # put and delete still not completed may not work yet
    def put(self, request, lesson_id):
        try:
            lesson = Lesson.objects.get(id=lesson_id) # get specified lesson from lesson_id
            serializer = LessonSerializer(lesson, data=request.data, partial=True) # serialize the lesson
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found."}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, lesson_id):
        try:
            lesson = Lesson.objects.get(id=lesson_id) # get specified lesson from lesson_id
            lesson.delete() # delete lesson from the database
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found."}, status=status.HTTP_404_NOT_FOUND)
        
class LessonView(APIView):
    """Retrieve an individual lesson"""
    def get(self, request, lesson_id):
        try:
            lesson = Lesson.objects.get(id=lesson_id) # get specified lesson from lesson_id
            serializer = LessonSerializer(lesson) # serialize the lesson
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Lesson.DoesNotExist:
            return Response({"error": "Lesson not found."}, status=status.HTTP_404_NOT_FOUND)

def sendEmail(to, subject, message):
    send_mail(subject, message, settings.EMAIL_HOST_USER, to, fail_silently=False)

class VerificationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        serializer = CreateUserSerializer(data=request.data)

        delInstance = Verification.objects.filter(email=email)
        try:
            delInstance.delete()
        except(delInstance.DoesNotExist):
               pass
        
        if(serializer.is_valid()):
            code = str(random.randint(100000, 999999))

            message = f'Your verification code: {code}'
            subject = 'Verification Code for House of Harmony Music'
            recipient = [email]
            sendEmail(recipient, subject, message)

            instance = Verification(email=email, code=code)
            instance.save()

            serializer = VerificationSerializer(instance)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerificationCheckView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Sets the variables
        email = request.data.get('email')
        enteredCode = request.data.get('code')

        # If no email is entered, return an error message
        if not email or not enteredCode:
            return Response({"error": "Email and code are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Grab the verification object associated with the email
        instance = Verification.objects.filter(email=email).first()

        if not instance:
            return Response({"error": "No verification code found for this email."}, status=status.HTTP_400_BAD_REQUEST)
        
        # Check if the entered code matches the generated one and act accordingly.
        if (str(instance.code) == str(enteredCode)):
            instance.delete() # This deletes the row from the database
            return Response({"message": "Verification successful."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid verification code."}, status=status.HTTP_400_BAD_REQUEST)
        
class EmailCommunicationView(APIView):
    """"Send email from user to site owner"""
    permission_classes = [AllowAny]
    throttle_classes = [UserRateThrottle, AnonRateThrottle]

    def post(self, request):
        name = request.data.get("name")
        email = request.data.get("email")
        question = request.data.get("question")

        try:
            validate_email(email)
            subject = 'House of Harmony Music Inquiry'
            message = f'Name: {name}\nEmail: {email}\n\nQuestion: {question}'

            email_message = EmailMessage(
                subject = subject,
                body = message,
                from_email = settings.EMAIL_HOST_USER,
                to = [settings.EMAIL_HOST_USER],
                reply_to = [email],
            )

            email_message.send(fail_silently=False)
            return Response({"message": "Email successfully sent."}, status=status.HTTP_200_OK)
        except ValidationError:
            return Response({"error": "Invalid email."}, status=status.HTTP_400_BAD_REQUEST)
        except SMTPException:
            return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception:
            return Response({"error": "Unknown error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MassEmailCommunicationView(APIView):
    """Superuser can send emails to all registered accounts"""
    def post(self, request):
        if not request.user.is_superuser:
            return Response({"error": "Not authorized to send mass emails."}, status=status.HTTP_403_FORBIDDEN)
        
        email_subject = request.data.get("subject")
        email_body = request.data.get("body")
        
        try:
            all_users = User.objects.all()
            email_messages = []

            for user in all_users:
                email_messages.append(
                    (email_subject, email_body, settings.EMAIL_HOST_USER, [user.email])
                )

            send_mass_mail(email_messages, fail_silently=False)
            return Response({"message": "Email successfully sent."}, status=status.HTTP_200_OK)
        except SMTPException:
            return Response({"error": "Failed to send email."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception:
            return Response({"error": "Unknown error."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RequestPasswordResetView(APIView):
    """Send email to user requesting password reset"""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = f"http://localhost:5173/password-reset/{user.id}/{token}"
            sendEmail([email], 'House of Harmony Music - Password Reset', f"Click the link to reset your password: {reset_url}")
            return Response({'success': 'Password reset email sent.'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        
class RequestUsernameResetView(APIView):
    """Send email to user requesting username reset"""
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = f"http://localhost:5173/username-reset/{user.id}/{token}"
            sendEmail([email], 'House of Harmony Music - Username Reset', f"Click the link to reset your username: {reset_url}")
            return Response({'success': 'Username reset email sent.'}, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetView(APIView):
    """Reset user password"""
    permission_classes = [AllowAny]

    def post(self, request, user_id, token):
        password = request.data.get("password")
        try:
            user = User.objects.get(id=user_id)
            if default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({"success": "Password reset."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

class UsernameResetView(APIView):
    """Reset username"""
    permission_classes = [AllowAny]

    def post(self, request, user_id, token):
        username = request.data.get("username")
        try:
            user = User.objects.get(id=user_id)
            if default_token_generator.check_token(user, token):
                if User.objects.filter(username=username).exists():
                    return Response({"error": "Username already taken."}, status=status.HTTP_400_BAD_REQUEST)
                
                user.username = username
                user.save()
                return Response({"success": "Username changed."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

def AddCourseToAccount(course_id, user_id):
    """Adds course to users account"""
    try:
        user = User.objects.get(id=user_id)
        account = Account.objects.get(user=user)
        course = Course.objects.get(id=course_id)
        account.courses.add(course)
        account.save    

        # Send confirmation email
        message = (
            f'Course Purchase Confirmation:\n'
            f'{user.username} has purchased the course: "{course.title}" for ${course.price}.\n\n'
            f'Thank you for your purchase! You can now start your journey with House of Harmony Music!\n'
            f'If you have any questions, feel free to contact us.'
        )
        subject = 'Course Purchase - House of Harmony Music'
        recipient = [user.email]
        sendEmail(recipient, subject, message)

    except User.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)        
    except Account.DoesNotExist:
        return Response({"error": "Account not found."}, status=status.HTTP_404_NOT_FOUND)
    except Course.DoesNotExist:
        return Response({"error": "Course not found."}, status=status.HTTP_404_NOT_FOUND)

stripe.api_key = settings.STRIPE_SECRET_KEY
class CreateCheckoutSessionView(APIView):
    """
        Stripe payment
        Creates a stripe checkout session which allows for a onetime payment
        Uses stripe API to handle all the payment process
    """
    def post(self, request):
        try:
            # Get course data
            course_id = request.data.get("course_id") 
            course = Course.objects.get(id=course_id)
            price = course.price * 100
            name = course.title

            # Set return urls
            success_url = f'http://localhost:5173/course-list/course/{course_id}?success=true'
            cancel_url = f'http://localhost:5173/course-list/course/{course_id}?canceled=true'

            # Skips checkout if course is free
            if price <= 0:
                AddCourseToAccount(course_id, request.user.id)
                return Response({"success": "Free course.", "redirect_url": success_url}, status=status.HTTP_202_ACCEPTED)

            # Create stripe checkout session
            checkout_session = stripe.checkout.Session.create(
                line_items = [{
                    'price_data': {
                        'currency' : 'usd',  
                        'product_data': { 'name': name },
                        'unit_amount': int(price),
                    },
                    'quantity' : 1
                }],
                mode = 'payment',
                success_url = success_url,
                cancel_url = cancel_url,
                metadata = {
                    'course_id': course_id,
                    'user_id': request.user.id,
                }
            )
            return Response({"checkout_url": checkout_session.url})
        except Course.DoesNotExist:
            return Response({"error": "Course not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Stripe error: {e}")
            return Response({"error": "An error occurred while creating checkout session"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@method_decorator(csrf_exempt, name='dispatch')
class CheckoutWebHookView(APIView):
    """
        Webhook for stripe
        When a payment is successfully recieved by stripe, checkout.session.completed event is created on stripe
        This function is triggered by that event to handle the course purchasing logic 
    """
    permission_classes = [AllowAny]
    
    def post(self , request):
        event = None
        payload = request.body
        sig_header = request.META['HTTP_STRIPE_SIGNATURE']
    
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
            )
        except ValueError as err:
            # Invalid payload
            return JsonResponse({"error": "Invalid payload"}, status=status.HTTP_400_BAD_REQUEST)
        except stripe.error.SignatureVerificationError as err:
            # Invalid signature
            return JsonResponse({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)
    
        # Handle the event
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            course_id = session['metadata']['course_id']
            user_id = session['metadata']['user_id']
            AddCourseToAccount(course_id, user_id)
            return JsonResponse({"success": "Payment complete."}, status=status.HTTP_202_ACCEPTED)