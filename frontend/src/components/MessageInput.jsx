// src/components/MessageInput.jsx
import { useState, useRef, useEffect } from "react";
import { SendHorizontal } from "lucide-react";
import "./MessageInput.css";

export default function MessageInput({ chatId, onSend, disabled = false }) {
  const [text, setText] = useState("");
  const textareaRef = useRef(null);

  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [text]);

  const handleSend = () => {
    const trimmed = text.trim();
    if (!trimmed) return;

    if (!chatId) {
      return;
    }

    onSend(trimmed);
    setText("");
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <form
      className="message-input-container"
      onSubmit={(e) => {
        e.preventDefault();
        handleSend();
      }}
    >
      <textarea
        ref={textareaRef}
        rows={1}
        className="message-input"
        placeholder="Ex: CVE-2024-..., SQL injection, buffer overflow..."
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={onKeyDown}
        disabled={disabled}
      />
      <button
        type="submit"
        className="send-button"
        disabled={!text.trim() || !chatId || disabled}
        aria-label="Envoyer"
      >
        <SendHorizontal size={18} />
      </button>
    </form>
  );
}
