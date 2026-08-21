// src/components/ChatWindow.jsx
import React from "react";
import "./ChatWindow.css";

const parseLinks = (text) => {
  if (!text) return "";
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts = text.split(urlRegex);
  return parts.map((part, i) => {
    if (part.match(urlRegex)) {
      return (
        <a key={i} href={part} target="_blank" rel="noopener noreferrer" style={{ color: "#3b82f6", textDecoration: "underline" }}>
          {part}
        </a>
      );
    }
    return part;
  });
};

export default function ChatWindow({ messages, selectedChatId }) {
  if (!selectedChatId) {
    return (
      <div className="empty-state">
        <h2>Aucun chat sélectionné !</h2>
      </div>
    );
  }

  if (messages.length === 0) {
    return (
      <div className="empty-state">
        <h2>Comment puis-je vous aider ?</h2>
      </div>
    );
  }

  return (
    <div className="chat-window">
      {messages.map((msg) => (
        <div
          key={msg.id}
          className={`message ${msg.sender === "Invité" || msg.sender === "Moi" ? "me" : ""}`}
        >
          <div className="content">{parseLinks(msg.content)}</div>
        </div>
      ))}
    </div>
  );
}
