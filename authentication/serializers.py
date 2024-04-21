from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth import authenticate
from authentication.models import User
    

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField(label="Password", style={'input_type': 'password'}, trim_whitespace=False)


    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                msg = 'No account with this username.'
                raise serializers.ValidationError(msg, code='authorization')
            
            user = authenticate(email=email, password=password)
            if not user:
                msg = 'Unable to authenticate with provided credentials.'
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = 'Must include "username" and "password".'
            raise serializers.ValidationError(msg, code='authorization')

        attrs['user'] = user
        return attrs
    

class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'username',
            'password',
        ]

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'username',
        ]