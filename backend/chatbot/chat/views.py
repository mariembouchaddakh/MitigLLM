# views.py
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Chat, Message
from .serializers import RegisterSerializer, ChatSerializer, MessageSerializer
from .inference import generate_response  # ✅ Nouveau

# ---------------- AUTHENTICATION ----------------

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            return Response({"refresh": str(refresh), "access": str(refresh.access_token)})
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

# ---------------- CHATS ----------------

class UserChatsView(generics.ListCreateAPIView):
    serializer_class = ChatSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Chat.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        if not self.request.user or not self.request.user.is_authenticated:
            raise NotAuthenticated("User must be authenticated.")
        print("🟡 Creating chat for user:", self.request.user)
        print("🟡 Data:", self.request.data)
        serializer.save(user=self.request.user)

# ---------------- MESSAGES ----------------

class ChatMessagesView(generics.ListCreateAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Message.objects.filter(chat_id=self.kwargs["chat_id"])

    def perform_create(self, serializer):
        serializer.save(chat_id=self.kwargs["chat_id"], sender=self.request.user)

# ---------------- MODEL INFERENCE ----------------

class ChatWithModelView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        prompt = request.data.get("prompt", "").strip()
        if not prompt:
            return Response({"error": "Prompt manquant"}, status=status.HTTP_400_BAD_REQUEST)

        answer = generate_response(prompt)
        return Response({"answer": answer})

# ---------------- AUTO REPLY ----------------

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def auto_reply_view(request, chat_id):
    print("🔥 auto_reply_view was CALLED")
    prompt = request.data.get("prompt", "").strip()
    if not prompt:
        return Response({"error": "Prompt manquant"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        chat = Chat.objects.get(id=chat_id, user=request.user)
    except Chat.DoesNotExist:
        return Response({"error": "Chat non trouvé"}, status=status.HTTP_404_NOT_FOUND)

    answer = generate_response(prompt)

    bot_msg = Message.objects.create(
        chat=chat,
        sender=None,
        content=answer
    )

    return Response(MessageSerializer(bot_msg).data, status=status.HTTP_201_CREATED)
