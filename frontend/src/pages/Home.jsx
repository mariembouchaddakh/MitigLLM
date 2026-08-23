// src/pages/Home.jsx
import { useNavigate } from "react-router-dom";
import { LogIn, ShieldCheck, UserRound } from "lucide-react";
import "./Home.css";

export default function Home() {
    const navigate = useNavigate();

    return (
        <div className="home-container">
            <main className="home-shell">
                <section className="home-copy">
                    <span className="home-kicker">Purple Team Assistant</span>
                    <h1>MitigLLM</h1>
                    <p>
                        Assistant spécialisé pour transformer une vulnérabilité ou une CVE
                        en recommandations de mitigation claires, techniques et exploitables.
                    </p>

                    <div className="home-buttons">
                        <button className="home-button primary" onClick={() => navigate("/chat/guest")}>
                            <UserRound size={18} />
                            Mode invité
                        </button>
                        <button className="home-button" onClick={() => navigate("/login")}>
                            <LogIn size={18} />
                            Se connecter
                        </button>
                    </div>
                </section>

                <section className="home-panel" aria-label="Aperçu du workflow">
                    <div className="panel-header">
                        <ShieldCheck size={20} />
                        <span>Workflow mitigation</span>
                    </div>
                    <ol>
                        <li>Analyser la description de vulnérabilité</li>
                        <li>Identifier le contexte technique</li>
                        <li>Générer les actions de mitigation</li>
                        <li>Préparer une réponse exploitable par l'analyste</li>
                    </ol>
                </section>
            </main>
        </div>
    );
}
