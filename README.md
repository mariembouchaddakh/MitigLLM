# MitigLLM : LLM Spécialisé en Cybersécurité pour la Génération de Mitigations

Ce projet a été développé dans le cadre d'un stage au sein de la **Purple Team de Keystone**. 
Il s'agit d'une application web complète intégrant un Modèle de Langage (LLM) spécialisé dans le domaine de la cybersécurité. Son objectif principal est de générer automatiquement des recommandations de mitigation précises et contextualisées à partir de descriptions de vulnérabilités (CVE).

---

## Fonctionnalités Principales

- **Génération de Mitigations Contextualisées** : Contrairement aux solutions génériques, le modèle fournit des réponses techniques précises adaptées aux failles (ex: Buffer Overflow, Injection SQL).
- **Architecture RAG (Retrieval-Augmented Generation)** : Intégration de bases de données de vulnérabilités pour enrichir le contexte du LLM.
- **Réduction des Hallucinations** : Le modèle (basé sur Mistral 7B) a été finement ajusté (Fine-tuning via QLoRA) sur des jeux de données spécialisés pour garantir des réponses fiables et exactes.
- **Interface Utilisateur Moderne** : Application web complète (Frontend React, Backend Django) avec authentification sécurisée et gestion d'historique de requêtes par utilisateur.

## Architecture Technique

Le système est composé de trois briques principales :

1. **Le Modèle de Langage (LLM)**
   - **Modèle de base** : Mistral 7B.
   - **Technique d'apprentissage** : Fine-tuning (QLoRA) sur des datasets fusionnés issus du NVD (National Vulnerability Database), GitHub Security Advisories et CWE.
   - **Déploiement** : Inféré en backend via PyTorch et la bibliothèque HuggingFace Transformers.

2. **Backend (Django)**
   - API REST gérant l'authentification des utilisateurs, la sauvegarde de l'historique des requêtes et l'interface de communication avec le modèle IA.
   - Base de données pour la traçabilité des actions.

3. **Frontend (React)**
   - Interface utilisateur interactive et fluide de type "Chatbot" permettant aux analystes (Blue Team / Purple Team) d'interagir intuitivement avec MitigLLM.

## Structure du Dépôt

```text
/
├── backend/            # Serveur Django, API REST, et intégration du modèle
│   └── chatbot/        # Application principale (models, views, urls)
├── frontend/           # Interface React (Create React App)
│   ├── src/            # Code source des composants React
│   └── public/         # Assets statiques
└── README.md
```

## Instructions d'Installation (Développement Local)

### 1. Prérequis
- Python 3.9+
- Node.js (v16+) & npm
- Accès à un GPU (recommandé pour l'inférence locale du modèle Mistral 7B)

### 2. Configuration du Backend (Django)

```bash
cd backend/chatbot

# Créer et activer un environnement virtuel
python -m venv venv
# Sur Windows : venv\Scripts\activate
# Sur Linux/Mac : source venv/bin/activate

# Installer les dépendances Python
pip install -r requirements.txt

# Appliquer les migrations de la base de données
python manage.py migrate

# Lancer le serveur de développement API
python manage.py runserver
```
Le backend sera actif sur `http://localhost:8000`.

### 3. Configuration du Frontend (React)

Ouvrez un nouveau terminal et exécutez :

```bash
cd frontend

# Installer les dépendances JavaScript
npm install

# Lancer l'interface utilisateur
npm start
```
L'application sera accessible sur `http://localhost:3000`.

---

*Projet réalisé par Mariem Bouchaddakh - Année 2024/2025.*
