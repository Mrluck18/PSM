import React from "react";
import "./PasswordInput.css";
import { usePasswordController } from "./PasswordController";

export default function PasswordView() {
  // Riceve stato e azioni dal Controller
  const {
    password,
    showPassword,
    strength,
    isChecking,
    validationError,
    richiestaAnalisiPassword,
    onToggleVisibility,
  } = usePasswordController();

  return (
    <main className="page">
      <section className="card">
        <header className="header">
          <div className="icon" aria-hidden="true">🛡️</div>
          <h1 className="title">Password Strength Meter</h1>
          <p className="subtitle">Verifica la sicurezza della tua password</p>
        </header>

        <div className="inputRow">
          <input
            className="input"
            type={showPassword ? "text" : "password"}
            value={password}
            onChange={(e) => richiestaAnalisiPassword(e.target.value)}
            placeholder="Inserisci password..."
            autoComplete="new-password"
            aria-label="Campo password"
          />
          <button
            className="toggle"
            type="button"
            onClick={onToggleVisibility}
            aria-label={showPassword ? "Nascondi password" : "Mostra password"}
          >
            {showPassword ? "Nascondi" : "Mostra"}
          </button>
        </div>

        {validationError && (
          <p style={{ color: '#ff3b3b', fontSize: '14px', marginTop: '8px' }}>
            Sono ammessi tutti i caratteri tranne quelli di controllo (es. tab)
          </p>
         )}
         
        <div className="barBg" aria-hidden="true">
          <div
            className="barFill"
            style={{
              width: `${strength.score}%`,
              background: strength.color,
              opacity: isChecking ? 0.5 : 1,
            }}
          />
        </div>

        <p className="status" role="status" aria-live="polite">
          {isChecking ? "Controllo database..." : strength.label}
        </p>

        {!isChecking && strength.suggestions?.length > 0 && (
          <ul
            style={{
              marginTop: "16px",
              paddingLeft: "20px",
              fontSize: "15px",
              opacity: 0.85,
              textAlign: "left",
              lineHeight: "1.6",
            }}
            aria-label="Suggerimenti per migliorare la password"
          >
            {strength.suggestions.map((msg, idx) => (
              <li key={idx}>{msg}</li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}

