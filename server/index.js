import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());

// allow your vite frontend to call the server
app.use(
    cors({
        origin: process.env.CLIENT_URL || "http://127.0.0.1:5173",
        credentials: true,
    })
);

// ---- In-memory stores (MVP only) ----
const pkceStore = new Map(); // state -> code_verifier
const tokenStore = {
    accessToken: null,
    refreshToken: null,
    expiresAt: 0,
};

// ---- Helpers ----
function base64url(buf) {
    return buf.toString("base64url");
}
function generateCodeVerifier() {
    return base64url(crypto.randomBytes(32));
}
function generateCodeChallenge(verifier) {
    return base64url(crypto.createHash("sha256").update(verifier).digest());
}
function mustEnv(key) {
    const v = process.env[key];
    if (!v) throw new Error(`Missing env var: ${key}`);
    return v;
}
function tokenValid() {
    return tokenStore.accessToken && Date.now() < tokenStore.expiresAt - 10_000;
}

// ---- Auth: start ----
app.get("/api/auth/spotify/start", (req, res) => {
    const clientId = mustEnv("SPOTIFY_CLIENT_ID");
    const redirectUri = mustEnv("SPOTIFY_REDIRECT_URI");

    const state = base64url(crypto.randomBytes(16));
    const verifier = generateCodeVerifier();
    const challenge = generateCodeChallenge(verifier);

    pkceStore.set(state, verifier);

    const params = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "playlist-modify-private", // keep it simple
        state,
        code_challenge_method: "S256",
        code_challenge: challenge,
        show_dialog: "true",
    });

    res.redirect(`https://accounts.spotify.com/authorize?${params.toString()}`);
});

// ---- Auth: callback ----
app.get("/api/auth/spotify/callback", async (req, res) => {
    const clientUrl = process.env.CLIENT_URL || "http://127.0.0.1:5173";

    try {
        const { code, state, error } = req.query;

        if (error) return res.redirect(`${clientUrl}/?spotify=error&reason=${error}`);
        if (!code) return res.redirect(`${clientUrl}/?spotify=error&reason=missing_code`);
        if (!state || !pkceStore.has(state))
            return res.redirect(`${clientUrl}/?spotify=error&reason=invalid_state`);

        const verifier = pkceStore.get(state);
        pkceStore.delete(state);

        const clientId = mustEnv("SPOTIFY_CLIENT_ID");
        const redirectUri = mustEnv("SPOTIFY_REDIRECT_URI");

        const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code,
                redirect_uri: redirectUri,
                client_id: clientId,
                code_verifier: verifier,
            }),
        });

        const tokenData = await tokenRes.json();
        if (!tokenRes.ok) {
            console.error("token exchange failed", tokenRes.status, tokenData);
            return res.redirect(`${clientUrl}/?spotify=error&reason=token_exchange_failed`);
        }

        tokenStore.accessToken = tokenData.access_token;
        tokenStore.refreshToken = tokenData.refresh_token || null;
        tokenStore.expiresAt = Date.now() + tokenData.expires_in * 1000;

        console.log("spotify connected");
        return res.redirect(`${clientUrl}/?spotify=connected`);
    } catch (e) {
        console.error("callback error", e);
        return res.redirect(`${clientUrl}/?spotify=error&reason=server_error`);
    }
});

// ---- Refresh token (optional but nice) ----
async function refreshIfNeeded() {
    if (tokenValid()) return;

    if (!tokenStore.refreshToken) {
        throw new Error("Not connected to Spotify (no refresh token).");
    }

    const clientId = mustEnv("SPOTIFY_CLIENT_ID");

    const r = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: tokenStore.refreshToken,
            client_id: clientId,
        }),
    });

    const data = await r.json();
    if (!r.ok) {
        console.error("refresh failed", r.status, data);
        throw new Error("Spotify refresh failed");
    }

    tokenStore.accessToken = data.access_token;
    tokenStore.expiresAt = Date.now() + data.expires_in * 1000;
}

// ---- Status endpoint ----
app.get("/api/spotify/status", async (req, res) => {
    res.json({ connected: !!tokenStore.accessToken && Date.now() < tokenStore.expiresAt });
});

// ---- Export endpoint ----
app.post("/api/spotify/export", async (req, res) => {
    try {
        await refreshIfNeeded();

        const { name, description, tracks } = req.body;

        if (!Array.isArray(tracks) || tracks.length === 0) {
            return res.status(400).json({ error: "tracks must be a non-empty array" });
        }

        const token = tokenStore.accessToken;

        // Create playlist (PRIVATE)
        const createRes = await fetch("https://api.spotify.com/v1/me/playlists", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${token}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                name: name || "TunedIn Blend",
                public: false,
                description: description || "Generated by TunedIn Blend",
            }),
        });

        const playlist = await createRes.json();
        if (!createRes.ok) {
            console.error("create playlist failed", createRes.status, playlist);
            return res.status(createRes.status).json({ error: playlist?.error?.message || "create failed" });
        }

        // Search each track -> collect URIs
        const uris = [];
        for (const t of tracks) {
            const title = (t.title || t.name || "").trim();
            const artistRaw = (t.artist || "").trim();
            if (!title || !artistRaw) continue;

            // use first artist if multiple
            const artist = artistRaw.split(/feat\.|ft\.|featuring|&|,| x | with /i)[0].trim();

            const q = `track:${title} artist:${artist}`;

            const searchRes = await fetch(
                `https://api.spotify.com/v1/search?${new URLSearchParams({
                    q,
                    type: "track",
                    limit: "1",
                })}`,
                { headers: { Authorization: `Bearer ${token}` } }
            );

            const searchData = await searchRes.json();
            const uri = searchData?.tracks?.items?.[0]?.uri;
            if (uri) uris.push(uri);
        }

        // Add in chunks of 100
        for (let i = 0; i < uris.length; i += 100) {
            const chunk = uris.slice(i, i + 100);

            const addRes = await fetch(`https://api.spotify.com/v1/playlists/${playlist.id}/tracks`, {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${token}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ uris: chunk }),
            });

            const addData = await addRes.json().catch(() => null);
            if (!addRes.ok) {
                console.error("add tracks failed", addRes.status, addData);
                return res.status(addRes.status).json({ error: addData?.error?.message || "add failed" });
            }
        }

        return res.json({
            ok: true,
            playlistId: playlist.id,
            playlistUrl: playlist.external_urls?.spotify,
            added: uris.length,
        });
    } catch (e) {
        console.error("export error", e);
        res.status(500).json({ error: e?.message || "server error" });
    }
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Server running on http://127.0.0.1:${port}`));
