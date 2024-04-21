from django.urls import path
from authentication.views import  LoginView, RegisterView, LogoutView, ProfileView


urlpatterns = [
    path('registration/', RegisterView.as_view(), name='registration'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='login'),
]