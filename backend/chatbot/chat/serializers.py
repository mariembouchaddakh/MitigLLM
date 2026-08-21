from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Chat, Message


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'password']

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password']
        )
        return user


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username']


# chat/serializers.py
class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['id', 'chat', 'sender', 'content', 'timestamp']
        extra_kwargs = {'chat': {'required': False}}  # <-- ajout


class ChatSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)  # ✅ mark user as read-only
    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Chat
        fields = ['id', 'user', 'title', 'created_at', 'messages']
