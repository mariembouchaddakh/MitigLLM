// src/pages/Chat.jsx  (instrumenté)
import React, { useState, useEffect } from "react";
import Sidebar from "../components/Sidebar";
import ChatWindow from "../components/chatWindow";
import MessageInput from "../components/MessageInput";
import { Menu } from "lucide-react";
import axios from "axios";
import "./Chat.css";

function Chat({ mode }) {
  const isGuest = mode === "guest";
  const token = localStorage.getItem("access");

  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [chats, setChats] = useState([]);
  const [selectedChatId, setSelectedChatId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [errorMessage, setErrorMessage] = useState(""); // <- pour l’UI

  /* ----------  FETCH / CREATE CHAT  ---------- */
  useEffect(() => {
    if (isGuest) {
      setChats([{ id: "guest", title: "Conversation invité" }]);
      setSelectedChatId("guest");
      setMessages([]);
      return;
    }

    axios
      .get("http://localhost:8000/api/chats/", {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => {
        setChats(res.data);
        if (res.data.length) setSelectedChatId(res.data[0].id);
      })
      .catch(() => {
        localStorage.removeItem("access");
        window.location.href = "/login";
      });
  }, [isGuest, token]);

  /* ----------  FETCH MESSAGES  ---------- */
  useEffect(() => {
    if (!selectedChatId) {
      setMessages([]);
      return;
    }
    if (isGuest) {
      setMessages([]);
      return;
    }

    axios
      .get(`http://localhost:8000/api/chats/${selectedChatId}/messages/`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      .then((res) => setMessages(res.data));
  }, [selectedChatId, isGuest, token]);

  /* ----------  SEND MESSAGE  ---------- */
  const sendMessage = async (text) => {
    const trimmed = text.trim();
    if (!trimmed) return;
    setErrorMessage(""); // reset

    const userMsg = {
      id: Date.now(),
      sender: isGuest ? "Invité" : "Moi",
      content: trimmed,
    };
    setMessages((prev) => [...prev, userMsg]);

    /* ----------  INVITÉ  ---------- */
    if (isGuest) {
      try {
        const res = await axios.post("http://localhost:8000/api/chat/", {
          prompt: trimmed,
        });
        const botMsg = {
          id: Date.now() + 1,
          sender: "Bot",
          content: res.data.answer,
        };
        setMessages((prev) => [...prev, botMsg]);
      } catch (err) {
        const errorMsg = {
          id: Date.now() + 1,
          sender: "Bot",
          content: "Erreur de réponse.",
        };
        setMessages((prev) => [...prev, errorMsg]);
      }
      return;
    }

    /* ----------  UTILISATEUR CONNECTÉ  ---------- */
    try {
      // 1) Enregistrement du message utilisateur
      console.log("Envoi user →", {
        url: `http://localhost:8000/api/chats/${selectedChatId}/messages/`,
        payload: { content: trimmed },
        token,
      });

      const { data: savedUserMsg } = await axios.post(
        `http://localhost:8000/api/chats/${selectedChatId}/messages/`,
        { content: trimmed },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setMessages((prev) => [...prev, savedUserMsg]);

      // 2) Appel au modèle
      console.log("Envoi auto-reply →", {
        url: `http://localhost:8000/api/chats/${selectedChatId}/auto-reply/`,
        payload: { prompt: trimmed },
        token,
      });

      const { data: botMsg } = await axios.post(
        `http://localhost:8000/api/chats/${selectedChatId}/auto-reply/`,
        { prompt: trimmed },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      // 3) Affichage + enregistrement de la réponse
      setMessages((prev) => [...prev, botMsg]);
    } catch (err) {
      console.error("❌ Erreur détaillée :", {
        status: err.response?.status,
        statusText: err.response?.statusText,
        data: err.response?.data,
      });
      console.error("❌ Erreur détaillée :");
      console.dir(err.response?.data, { depth: null });

      // Affiche l’erreur brute dans une alerte
      alert(JSON.stringify(err.response?.data, null, 2));
    }
  };

  /* ----------  CREATE CHAT  ---------- */
  const createChat = (customTitle) => {
    const title = customTitle || "Nouveau chat";
    if (isGuest) {
      setMessages([]);
      return;
    }
    axios
      .post(
        "http://localhost:8000/api/chats/",
        { title },
        { headers: { Authorization: `Bearer ${token}` } }
      )
      .then((res) => {
        setChats((c) => [res.data, ...c]);
        setSelectedChatId(res.data.id);
        setMessages([]);
      });
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
          >
            <Menu size={20} />
          </button>
          <span className="title">{isGuest ? "Invité" : "Chat"}</span>
        </header>

        {/* Optionnel : afficher l’erreur */}
        {errorMessage && (
          <div style={{ color: "red", padding: "0.5rem" }}>
            {errorMessage}
          </div>
        )}

        <ChatWindow messages={messages} selectedChatId={selectedChatId} />
        <MessageInput chatId={selectedChatId} onSend={sendMessage} />
      </main>
    </div>
  );
}

export default Chat;