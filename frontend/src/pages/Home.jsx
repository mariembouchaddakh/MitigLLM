// src/pages/Home.jsx
import { useNavigate } from "react-router-dom";
import "./Home.css";

export default function Home() {
    const navigate = useNavigate();

    return (
        <div className="home-container">
            <h1>Bienvenue sur MitigLLM</h1>
            <p>Choisissez votre mode d’accès :</p>

            <div className="home-buttons">
                <button className="home-button guest" onClick={() => navigate("/chat/guest")}>
                    Continuer en tant qu’invité
                </button>
                <button className="home-button" onClick={() => navigate("/login")}>
                    Se connecter
                </button>
            </div>
        </div>
    );
}