import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import "./Register.css";

function Register() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      await api.post("/register/", {
        username,
        password,
      });
      setSuccess("Compte créé avec succès ! Vous pouvez maintenant vous connecter.");
      setUsername("");
      setPassword("");

      setTimeout(() => {
        navigate("/login");
      }, 2000);
    } catch (err) {
      if (err.response && err.response.data) {
        setError("Erreur : " + JSON.stringify(err.response.data));
      } else {
        setError("Erreur lors de la création du compte.");
      }
    }
  };

  return (
    <div className="register-container">
      <form className="auth-card" onSubmit={handleRegister}>
        <span className="auth-eyebrow">MitigLLM</span>
        <h2>Créer un compte</h2>
        <p>Crée une session pour conserver tes conversations et analyses.</p>
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
        <button type="submit">S'inscrire</button>
        {success && <p className="auth-success">{success}</p>}
        {error && <p className="auth-error">{error}</p>}
        <p className="auth-switch">
          Déjà un compte ? <Link to="/login">Se connecter</Link>
        </p>
      </form>
    </div>
  );
}

export default Register;
