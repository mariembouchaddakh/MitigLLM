import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Chat from "./pages/Chat";

function App() {
  return (
    <Router>
      <Routes>
        {/* Page d’accueil SANS rediriger */}
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        {/* Utilisateur connecté : /chat */}
        <Route
          path="/chat"
          element={
            localStorage.getItem("access") ? (
              <Chat mode="user" />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />

        {/* Invité : /chat/guest SANS restriction */}
        <Route path="/chat/guest" element={<Chat mode="guest" />} />

        {/* Fallback sur Home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}
export default App;