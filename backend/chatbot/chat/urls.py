from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    UserChatsView,
    ChatMessagesView,
    ChatWithModelView,
    auto_reply_view
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('chats/', UserChatsView.as_view(), name='user-chats'),
    path('chats/<int:chat_id>/messages/', ChatMessagesView.as_view(), name='chat-messages'),
    path('chat/', ChatWithModelView.as_view(), name='chat-model'),
    path('chats/<int:chat_id>/auto-reply/', auto_reply_view, name='auto-reply'),
]
