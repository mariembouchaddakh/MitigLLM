// src/components/ChatWindow.jsx
import "./ChatWindow.css";

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
        <h2>Comment puis-je vous aider&nbsp;?</h2>
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
          <div className="content">{msg.content}</div>
        </div>
      ))}
    </div>
  );
}
