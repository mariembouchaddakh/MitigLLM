import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../components/Sidebar";
import ChatWindow from "../components/chatWindow";
import MessageInput from "../components/MessageInput";
import { Menu, ShieldCheck, LogOut } from "lucide-react";
import { api, authHeaders } from "../api";
import "./Chat.css";

function Chat({ mode }) {
  const isGuest = mode === "guest";
  const navigate = useNavigate();

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [chats, setChats] = useState([]);
  const [selectedChatId, setSelectedChatId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [errorMessage, setErrorMessage] = useState("");
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    if (isGuest) {
      setChats([{ id: "guest", title: "Analyse rapide" }]);
      setSelectedChatId("guest");
      setMessages([]);
      return;
    }

    api
      .get("/chats/", { headers: authHeaders() })
      .then((res) => {
        setChats(res.data);
        setSelectedChatId(res.data[0]?.id || null);
      })
      .catch(() => {
        localStorage.removeItem("access");
        localStorage.removeItem("refresh");
        navigate("/login", { replace: true });
      });
  }, [isGuest, navigate]);

  useEffect(() => {
    if (!selectedChatId) {
      setMessages([]);
      return;
    }
    if (isGuest) {
      setMessages([]);
      return;
    }

    api
      .get(`/chats/${selectedChatId}/messages/`, { headers: authHeaders() })
      .then((res) => setMessages(res.data))
      .catch(() =>
        setErrorMessage("Impossible de charger les messages de cette conversation.")
      );
  }, [selectedChatId, isGuest]);

  const sendMessage = async (text) => {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;

    setErrorMessage("");
    setIsSending(true);
    const userMsg = {
      id: `local-${Date.now()}`,
      sender: isGuest ? "Invité" : "Moi",
      content: trimmed,
    };
    setMessages((prev) => [...prev, userMsg]);

    try {
      if (isGuest) {
        const { data } = await api.post("/chat/", { prompt: trimmed });
        setMessages((prev) => [
          ...prev,
          {
            id: `bot-${Date.now()}`,
            sender: "Bot",
            content: data.answer || "Aucune réponse générée.",
          },
        ]);
        return;
      }

      await api.post(
        `/chats/${selectedChatId}/messages/`,
        { content: trimmed },
        { headers: authHeaders() }
      );

      const { data: botMsg } = await api.post(
        `/chats/${selectedChatId}/auto-reply/`,
        { prompt: trimmed },
        { headers: authHeaders() }
      );

      setMessages((prev) => [
        ...prev,
        {
          id: botMsg.id || `bot-${Date.now()}`,
          sender: botMsg.sender || "Bot",
          content: botMsg.content || botMsg.answer || "Aucune réponse générée.",
        },
      ]);
    } catch (err) {
      setErrorMessage(
        err.response?.data?.error ||
          err.response?.data?.detail ||
          "Le backend ne répond pas. Vérifie que Django est lancé sur le port 8000."
      );
    } finally {
      setIsSending(false);
    }
  };

  const createChat = (customTitle) => {
    const title = customTitle || "Nouveau chat";
    if (isGuest) {
      setMessages([]);
      return;
    }
    api
      .post(
        "/chats/",
        { title },
        { headers: authHeaders() }
      )
      .then((res) => {
        setChats((c) => [res.data, ...c]);
        setSelectedChatId(res.data.id);
        setMessages([]);
      })
      .catch(() => setErrorMessage("Impossible de créer une conversation."));
  };

  const logout = () => {
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    navigate("/");
  };

  return (
    <div className="app">
      <aside className={`kimi-sidebar ${sidebarOpen ? "open" : ""}`}>
        <Sidebar
          chats={chats}
          activeId={selectedChatId}
          onSelectChat={setSelectedChatId}
          onNewChat={createChat}
        />
      </aside>

      <main className={`main ${sidebarOpen ? "with-sidebar" : ""}`}>
        <header className="header">
          <button
            className="sidebar-toggle"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            aria-label="Afficher ou masquer les conversations"
          >
            <Menu size={20} />
          </button>
          <div className="header-title">
            <ShieldCheck size={18} />
            <span>MitigLLM</span>
          </div>
          <div className="header-actions">
            <span className="mode-pill">{isGuest ? "Mode invité" : "Session analyste"}</span>
            {!isGuest && (
              <button className="logout-button" onClick={logout} aria-label="Se déconnecter">
                <LogOut size={17} />
              </button>
            )}
          </div>
        </header>

        {errorMessage && (
          <div className="error-banner" role="alert">
            {errorMessage}
          </div>
        )}

        <ChatWindow
          messages={messages}
          selectedChatId={selectedChatId}
          isSending={isSending}
        />
        <MessageInput chatId={selectedChatId} onSend={sendMessage} disabled={isSending} />
      </main>
    </div>
  );
}

export default Chat;
