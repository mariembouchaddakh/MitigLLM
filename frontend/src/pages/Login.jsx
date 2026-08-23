import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import "./Login.css";

function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");

    try {
      const res = await api.post("/login/", {
        username,
        password,
      });

      localStorage.setItem("access", res.data.access);
      localStorage.setItem("refresh", res.data.refresh);
      navigate("/chat");
    } catch (err) {
      if (err.response && err.response.data) {
        setError(err.response.data.error || err.response.data.detail || "Identifiants invalides");
      } else {
        setError("Impossible de joindre le serveur Django.");
      }
    }
  };

  return (
    <div className="login-container">
      <form className="auth-card" onSubmit={handleLogin}>
        <span className="auth-eyebrow">MitigLLM</span>
        <h2>Connexion analyste</h2>
        <p>Accède à ton historique et continue tes analyses de mitigation.</p>
        <input
          type="text"
          placeholder="Nom d'utilisateur"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Mot de passe"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="submit">Se connecter</button>
        {error && <p className="auth-error">{error}</p>}
        <p className="auth-switch">
          Pas de compte ? <Link to="/register">Créer un compte</Link>
        </p>
      </form>
    </div>
  );
}

export default Login;
