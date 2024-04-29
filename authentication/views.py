from django.contrib.auth import logout
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import views, generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.serializers import  LoginSerializer, UserRegisterSerializer, UserSerializer, ConfirmationCodeSerializer
from authentication.permissions import IsOwnerOrReadOnly
from authentication.models import User, OTP
from rest_framework.exceptions import AuthenticationFailed



class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        """
        Login a user.

        Login a user with the provided information. This endpoint expects a payload containing user details.
        """
        username = request.data["username"]
        password = request.data["password"]

        user = User.objects.filter(username=username).first()

        if user is None:
            return Response({"error": "User not found!"}, status.HTTP_404_NOT_FOUND)
        if not user.check_password(password):
            raise AuthenticationFailed({"error": "Incorrect password!"})

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "id": user.id,
                "username": user.username,
                "access": str(refresh.access_token),
                "refresh": str(refresh),
            }
        )



class LogoutView(views.APIView):

    def post(self, request, format=None):
        """
        Logout a user.

        Logout a user with the provided information. This endpoint expects a payload containing user details.
        """
        logout(request)
        return Response(None, status=status.HTTP_204_NO_CONTENT)



class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)


    def post(self, request, *args, **kwargs):
        """
        Register a new user.

        Creates a new user with the provided information. This endpoint expects a payload containing user details.
        """
        serializer = UserRegisterSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({'data' : serializer.data}, status=status.HTTP_201_CREATED)
        return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)



class ProfileView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]
    parser_classes = (MultiPartParser, FormParser)

    @swagger_auto_schema(
        responses={200: UserSerializer(many=True)},
        manual_parameters=[
            openapi.Parameter(
                "id",
                in_=openapi.IN_PATH,
                type=openapi.TYPE_INTEGER,
                description="Find with User ID",
            ),
            openapi.Parameter(
                "username",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description="Find with Username",
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        """
        Get the user info.

        Get the user info. This endpoint expects a payload containing user details.
        """
        queryset = self.filter_queryset(self.get_queryset())
        username = request.query_params.get("username")
        id = request.query_params.get("id")

        if username:
            queryset = queryset.filter(username=username)
        if id:
            queryset = queryset.filter(id=id)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        



class ConfirmCodeView(generics.GenericAPIView):
    serializer_class = ConfirmationCodeSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)


    @swagger_auto_schema(tags=['Authentication'],)
    
    def post(self, request):
        """
        Confirm a user email.

        Confirm a user email with the code. This endpoint expects a payload containing user details.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data.get('code')
        try:
            confirmation_code = OTP.objects.get(otp=code)
        except OTP.DoesNotExist:
            return Response({"error": "Invalid or already confirmed code."}, status=400)

        user = confirmation_code.user
        user.is_email_verified = True
        user.save()
        confirmation_code.delete()

        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Code confirmed successfully.",
            'user_id': str(user.id),
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        })