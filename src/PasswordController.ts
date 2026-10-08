import { useState, useEffect } from "react";
import { calcoloRobustezza, Strength } from "./strengthModel";

const INITIAL_STRENGTH: Strength = {
  entropyBits: 0,
  score: 0,
  label: "Inizia a digitare…",
  color: "#2d7dff",
  suggestions: [],
};

export function usePasswordController() {
  // Stati interni del Controller
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  
  // Stato per il risultato
  const [strength, updateUI] = useState<Strength>(INITIAL_STRENGTH);
  // Stato per il caricamento (check API in corso)
  const [isChecking, setIsChecking] = useState(false);

  useEffect(() => {
    // Debounce: non chiamare API ad ogni tasto, aspetta che l'utente si fermi un attimo
    
    const timer = setTimeout(async () => {
      if (!password) {
        updateUI(INITIAL_STRENGTH);
        return;
      }

      // Invia richiesta di analisi al Model
      setIsChecking(true);
      try {
        const result = await calcoloRobustezza(password);
        // Aggiorna lo stato con il punteggio ricevuto dal Model
        updateUI(result); // Inizia loading
      } catch (error) {
        console.error(error);
        // In caso di errore, mantiene lo stato precedente
      } finally {
        setIsChecking(false); // Fine loading
      }
    }, 500);  // 500 ms di ritardo

    return () => clearTimeout(timer); // Cleanup se l'utente digita ancora
  }, [password]);

  // Gestisce toggle visibilità password
  const handleToggleVisibility = () => {
    setShowPassword((prev) => !prev);
  };
  
  // Gestisce input dell'utente dalla View
  const [validationError, setValidationError] = useState(false);

  const handlePasswordChange = (newPassword: string) => {
    // NIST 3.1.1: accetta Unicode e spazio, vieta solo i caratteri di controllo
    const hasInvalidChars = /[\x00-\x1F\x7F]/.test(newPassword);

    if (hasInvalidChars && newPassword !== "") {
      setValidationError(true);
      setTimeout(() => setValidationError(false), 2000);
      return; // NON aggiorna password
    }
  
  setPassword(newPassword);
  setValidationError(false);
  };

  // API pubblica del Controller per la View
  return {
    // Stato da visualizzare
    password,
    showPassword,
    strength,
    isChecking,
    validationError,
    // Azioni disponibili
    richiestaAnalisiPassword: handlePasswordChange,
    onToggleVisibility: handleToggleVisibility,
  };
}

