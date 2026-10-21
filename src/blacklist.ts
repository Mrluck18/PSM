import { sha1 } from "./cryptoUtils";

// null: file non ancora caricato. Set vuoto: caricamento fallito (fallback)
let blacklistSet: Set<string> | null = null;
let loadingPromise: Promise<void> | null = null;

async function loadBlacklist(): Promise<void> {
    if (blacklistSet !== null) return;

    // Evita richieste parallele durante il primo caricamento
    if (loadingPromise) {
        await loadingPromise;
        return;
    }

    loadingPromise = (async () => {
        try {
            const response = await fetch("/top100k_hashes.txt");
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const text = await response.text();

            blacklistSet = new Set(
                text
                    .split("\n")
                    .map((line) => line.trim())
                    .filter((line) => line.length === 40)
            );
        } catch (error) {
            console.warn("Impossibile caricare la blacklist locale:", error);
            blacklistSet = new Set();
        } finally {
            loadingPromise = null;
        }
    })();

    await loadingPromise;
}

export async function isInBlacklist(pwd: string): Promise<boolean> {
    await loadBlacklist();
    // Minuscolo per rendere il controllo case-insensitive
    const hash = await sha1(pwd.toLowerCase());
    return blacklistSet!.has(hash);
}

export async function getBlacklistSet(): Promise<Set<string>> {
    await loadBlacklist();
    return blacklistSet!;
}