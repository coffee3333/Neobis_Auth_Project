from django.contrib.auth.models import User
from rest_framework import serializers
from authentication.models import User, OTP
from config import settings
from django.core.mail import send_mail



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
        user = User.objects.create_user(**validated_data)
        # Send the OTP to the user's email
        otp_code = OTP.generate_otp()
        OTP.objects.create(user=user, otp=otp_code)
        subject = 'Password OTP'
        message = f'Your OTP is: {otp_code}'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list)
        return user



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'username',
            'is_email_verified',
        ]


class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password', 'placeholder': 'Password'}
    )

    class Meta:
        model = User
        fields = [
            "username",
            "password",
        ]



class ConfirmationCodeSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=4)

    def validate(self, data):
        code = data.get('code')

        try:
            otp_obj = OTP.objects.get(otp=code)
            if otp_obj.is_expired:
                raise serializers.ValidationError({'error': "OTP has expired."})
        except OTP.DoesNotExist:
            raise serializers.ValidationError({'error': "Invalid OTP."})

        return data