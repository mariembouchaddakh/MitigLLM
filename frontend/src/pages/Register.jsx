import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
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
      const res = await axios.post("http://localhost:8000/api/register/", {
        username,
        password,
      });
      setSuccess("Compte créé avec succès ! Vous pouvez maintenant vous connecter.");
      setUsername("");
      setPassword("");

      // Optionnel : rediriger vers la page login après 2 secondes
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
      <h2>Créer un compte</h2>
      <form onSubmit={handleRegister}>
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
      </form>
      {success && <p style={{ color: "green" }}>{success}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}
      <p>
        Déjà un compte ? <a href="/login">Se connecter</a>
      </p>
    </div>
  );
}

export default Register;
