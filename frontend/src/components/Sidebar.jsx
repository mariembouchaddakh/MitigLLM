// src/components/Sidebar.jsx
import { Plus, MessageSquare, Shield } from "lucide-react";
import "./Sidebar.css";

export default function Sidebar({ chats, activeId, onSelectChat, onNewChat }) {
  const promptTitle = () => {
    const title = prompt("Nom de la conversation :")?.trim();
    onNewChat(title || "Nouveau chat");
  };

  return (
    <div className="sidebar-inner">
      <div className="sidebar-brand">
        <Shield size={20} />
        <div>
          <strong>MitigLLM</strong>
          <span>Cybersecurity assistant</span>
        </div>
      </div>

      <button className="sidebar-new" onClick={promptTitle}>
        <Plus size={18} /> Nouveau chat
      </button>

      <ul>
        {chats.map((c) => (
          <li
            key={c.id}
            className={c.id === activeId ? "active" : ""}
            onClick={() => onSelectChat(c.id)}
          >
            <MessageSquare size={16} />
            <span>{c.title}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
