from django.contrib.auth import login, logout
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import views, generics, permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from authentication.serializers import  LoginSerializer, UserRegisterSerializer, UserSerializer
from authentication.permissions import IsOwnerOrReadOnly
from authentication.models import User


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        """
        Login a user.

        Login a user with the provided information. This endpoint expects a payload containing user details.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        refresh = RefreshToken.for_user(user)

        return Response({
            'user': user.username,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }, status=status.HTTP_202_ACCEPTED)



class LogoutView(views.APIView):

    def post(self, request, format=None):
        """
        Logout a user.

        Logout a user with the provided information. This endpoint expects a payload containing user details.
        """
        logout(request)
        return Response(None, status=status.HTTP_204_NO_CONTENT)



class RegisterView(generics.CreateAPIView):
    serializer_class = UserRegisterSerializer
    permission_classes = (permissions.AllowAny,)
    parser_classes = (MultiPartParser, FormParser)


    def post(self, request, *args, **kwargs):
        serializer = UserRegisterSerializer(data=request.data)

        """
        Register a new user.

        Creates a new user with the provided information. This endpoint expects a payload containing user details.
        """
        if serializer.is_valid():
            serializer.save()
            return Response({serializer.data}, status=status.HTTP_201_CREATED)
        return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]


    @swagger_auto_schema(
        operation_description="Этот эндпоинт позволяет получить "
        "Информацию пользователя. Вы можете применять ",
        responses={200: UserSerializer(many=True)},
        manual_parameters=[
            openapi.Parameter(
                "username",
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description="Найти User по username тура.",
            ),
        ],
    )
    def get(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        username = request.query_params.get("username")

        if username:
            queryset = queryset.filter(username=username)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
        
