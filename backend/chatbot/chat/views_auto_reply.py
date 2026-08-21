# views_auto_reply.py
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Chat, Message
from .serializers import MessageSerializer
from .inference import generate_response  # ✅ Nouveau

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def auto_reply_view(request, chat_id):
    print("🔥 auto_reply_view has been called")
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

    print("📥 Prompt:", prompt)
    print("🟢 Final Answer:", answer)

    return Response(MessageSerializer(bot_msg).data, status=status.HTTP_201_CREATED)
