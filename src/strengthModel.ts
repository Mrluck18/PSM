import { sha1 } from "./cryptoUtils";
import { isInBlacklist } from "./blacklist";

export type Strength = {
  baseScore: number;
  score: number;
  label: string;
  color: string;
  suggestions: string[];
};

export type PatternType = "REPETITION" | "SEQUENCE" | "KEYBOARD" | "DATE";

export type PatternMatch = {
  type: PatternType;
  segment: string;
  start: number; // incluso, indice nella password originale
  end: number;   // escluso
  penalty: number;
};

async function richiediRange(prefissoHash: string): Promise<string> {
  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefissoHash}`);
  if (!response.ok) throw new Error("Network error");
  return await response.text(); // listaSuffissi 
}

function cercaSuffisso(listaSuffissi: string, suffisso: string): boolean {
  const regex = new RegExp(`^${suffisso}:`, "m");
  return regex.test(listaSuffissi);
}  
  
async function checkPwned(password: string): Promise<boolean> {
  if (!password) return false;
  // 1. Calcola Hash SHA-1
  const hash = await sha1(password);
  
  // 2. Prendi i primi 5 caratteri (prefix) e il resto (suffix)
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);

  try {
    const listaSuffissi = await richiediRange(prefix);
    return cercaSuffisso(listaSuffissi, suffix);
  } catch (err) {
    console.warn("Impossibile verificare HIBP, ignoro check online.", err);
    return false; // Fallback sicuro: assumiamo non compromessa se offline
  }
}

function calcolaScoreNIST(pwd: string): number {
  const L = pwd.length;
  if (L < 8) return 0;
  let base = 0;
  if (L >= 8)  base += 20;  // 20 → Debole
  if (L >= 12) base += 17;  // 37 → Media
  if (L >= 15) base += 30;  // 67 → Forte
  if (L >= 20) base += 13;  // 80 → massimo
  return base;
}

function computeLabelAndColor( score: number, L: number, isCompromised: boolean): { label: string; color: string } {
  if (isCompromised) {
    return {
      label:
          "Questa password è apparsa in database pubblici di violazioni di dati. " +
          "Sostituiscila con una frase lunga o una sequenza casuale di parole.",
      color: "#ff0000",
    };
  }

  // "Forte" richiede esplicitamente almeno 15 caratteri
  if (score >= 67 && L >= 15) return { label: "Forte", color: "#00d084" };
  if (score >= 34 && L >= 8)  return { label: "Media", color: "#ffd000" };
  return { label: "Debole", color: "#ff3b3b" };
}

function penalitaPerLunghezza(base: number, len: number, minLen: number): number {
  return Math.min(25, base + 3 * (len - minLen));
}

export function detectRepeatedChars(pwd: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const regex = /(.)\1{2,}/giu; // 3 o più caratteri uguali di seguito
  let m: RegExpExecArray | null;

  while ((m = regex.exec(pwd)) !== null) {
    matches.push({
      type: "REPETITION",
      segment: m[0],
      start: m.index,
      end: m.index + m[0].length,
      penalty: penalitaPerLunghezza(10, m[0].length, 3),
    });
  }
  return matches;
}

function codiceNormalizzato(pwd: string, i: number): number {
  const code = pwd.charCodeAt(i);
  return code >= 65 && code <= 90 ? code + 32 : code; // A-Z → a-z
}

function tipoCarattere(code: number): "cifra" | "lettera" | null {
  if (code >= 48 && code <= 57) return "cifra";
  if (code >= 97 && code <= 122) return "lettera";
  return null;
}

export function detectSequences(pwd: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  let start = 0;

  while (start < pwd.length - 1) {
    const c0 = codiceNormalizzato(pwd, start);
    const c1 = codiceNormalizzato(pwd, start + 1);
    const tipo = tipoCarattere(c0);
    const passo = c1 - c0;

    if (tipo === null || tipoCarattere(c1) !== tipo || (passo !== 1 && passo !== -1)) {
      start++;
      continue;
    }

    let end = start + 2;
    while (
        end < pwd.length &&
        tipoCarattere(codiceNormalizzato(pwd, end)) === tipo &&
        codiceNormalizzato(pwd, end) - codiceNormalizzato(pwd, end - 1) === passo
        ) {
      end++;
    }

    if (end - start >= 4) {
      matches.push({
        type: "SEQUENCE",
        segment: pwd.slice(start, end),
        start,
        end,
        penalty: penalitaPerLunghezza(12, end - start, 4),
      });
    }
    start = end - 1;
  }
  return matches;
}

const RIGHE_TASTIERA = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
const RIGHE_BIDIREZIONALI = RIGHE_TASTIERA.flatMap((r) => [
  r,
  [...r].reverse().join(""),
]);

export function detectKeyboardPatterns(pwd: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  let i = 0;

  while (i < pwd.length) {
    let migliore = 0;

    for (const riga of RIGHE_BIDIREZIONALI) {
      const idx = riga.indexOf(pwd[i].toLowerCase());
      if (idx === -1) continue;

      let k = 1;
      while (
          i + k < pwd.length &&
          idx + k < riga.length &&
          riga[idx + k] === pwd[i + k].toLowerCase()
          ) {
        k++;
      }
      if (k > migliore) migliore = k;
    }

    if (migliore >= 4) {
      matches.push({
        type: "KEYBOARD",
        segment: pwd.slice(i, i + migliore),
        start: i,
        end: i + migliore,
        penalty: penalitaPerLunghezza(15, migliore, 4),
      });
      i += migliore;
    } else {
      i++;
    }
  }
  return matches;
}

function isDataValida(g: number, m: number, a: number): boolean {
  if (a < 1900 || a > 2099 || m < 1 || m > 12 || g < 1) return false;
  return g <= new Date(a, m, 0).getDate(); // giorni del mese, anni bisestili inclusi
}

export function detectDates(pwd: string): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const regex = /\d+/g; // gruppi di cifre consecutive
  let m: RegExpExecArray | null;

  while ((m = regex.exec(pwd)) !== null) {
    const cifre = m[0];
    const start = m.index;
    const end = start + cifre.length;

    if (cifre.length === 8) {
      const g = Number(cifre.slice(0, 2));
      const mese = Number(cifre.slice(2, 4));
      const a = Number(cifre.slice(4, 8));
      if (isDataValida(g, mese, a)) {
        matches.push({ type: "DATE", segment: cifre, start, end, penalty: 20 });
      }
    } else if (cifre.length === 4 && /^(19|20)/.test(cifre)) {
      matches.push({ type: "DATE", segment: cifre, start, end, penalty: 15 });
    }
  }
  return matches;
}

function controlloPattern(pwd: string): boolean {
  const lower = pwd.toLowerCase();

  // 1. Caratteri ripetuti (es. "aaa")
  if (/(.)\1\1/.test(lower)) return true;

  // 2. Sequenze numeriche (es. "1234", "4321")
  if (/0123|1234|2345|3456|4567|5678|6789|7890/.test(lower)) return true;
  if (/0987|9876|8765|7654|6543|5432|4321|3210/.test(lower)) return true;

  // 3. Sequenze alfabetiche (es. "abcd", "dcba")
  if (/abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|ijkl|jklm|klmn|lmno|mnop|nopq|opqr|pqrs|qrst|rstu|stuv|tuvw|uvwx|vwxy|wxyz/.test(lower)) return true;

  // 4. Tastiera QWERTY (es. "qwer", "asdf")
  if (/qwer|wert|erty|rtyu|tyui|yuio|uiop/.test(lower)) return true;
  if (/asdf|sdfg|dfgh|fghj|ghjk|hjkl/.test(lower)) return true;
  if (/zxcv|xcvb|cvbn|vbnm/.test(lower)) return true;

  // 5. Anni comuni (19xx o 20xx)
  if (/(19|20)\d{2}/.test(lower)) return true;

  return false;
}

function getSuggestions(pwd: string, hasPattern: boolean, isCompromised: boolean): string[] {
  const suggestions: string[] = [];

  if (isCompromised) {
    return []; 
  }

  if (pwd.length < 8) {
    suggestions.push("Usa almeno 8 caratteri.");
  }
  if (hasPattern) {
    suggestions.push("Evita sequenze comuni (es. '1234', 'abcd') o caratteri ripetuti.");
  }
  if (suggestions.length === 0 && pwd.length < 12) {
    suggestions.push("Allunga la password con più parole o caratteri casuali.");
  }

  return suggestions;
}

export async function calcoloRobustezza(pwd: string): Promise<Strength> {
  if (!pwd) {
    return { baseScore: 0, score: 0, label: "Inizia a digitare…", color: "#2d7dff", suggestions: []};
  }

  const base = calcolaScoreNIST(pwd);
  const hasPattern = controlloPattern(pwd);

// Controllo locale primario: nessuna richiesta di rete per le password più comuni
  const isBlacklisted = await isInBlacklist(pwd);

// HIBP solo come fallback, se la blacklist locale non ha trovato la password
  const isPwned = isBlacklisted ? false : await checkPwned(pwd);

  const isCompromised = isBlacklisted || isPwned;

  const score = isCompromised ? 0 : base;

  const { label, color } = computeLabelAndColor(score, pwd.length, isCompromised);

  const suggestions = getSuggestions(pwd, hasPattern, isCompromised);

  return { baseScore: base, score, label, color, suggestions };

} 
