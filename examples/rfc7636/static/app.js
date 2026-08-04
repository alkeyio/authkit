(function () {
    const state = {
        step: -1,
        maxStep: -1,
        loading: false,
        scopes: [],
        selectedScopes: [],
        challengeMethod: 'S256',
        codeVerifier: '',
        codeChallenge: '',
        authResponse: null,  // { location, code } from GET /authorize
        tokenResponse: null, // { status, data } from POST /token
    };
    let fetchGen = 0;

    const CHALLENGE_METHOD_HINTS = {
        S256: 'Recommended. code_challenge = BASE64URL(SHA256(code_verifier)). The server cannot derive the verifier from the challenge (RFC 7636 §4.2).',
        plain: 'code_challenge = code_verifier. Only use when S256 is not available on the client platform (RFC 7636 §4.2).',
    };

    // ---- PKCE helpers ----
    function randVerifier() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let out = '';
        for (let i = 0; i < 64; i++) out += chars[Math.floor(Math.random() * chars.length)];
        return out;
    }

    async function computeChallenge(verifier, method) {
        if (method === 'plain') return verifier;
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        return btoa(String.fromCharCode(...new Uint8Array(buf)))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    async function refreshPKCE() {
        state.codeVerifier = randVerifier();
        state.codeChallenge = await computeChallenge(state.codeVerifier, state.challengeMethod);
        document.getElementById('codeVerifier').value = state.codeVerifier;
        document.getElementById('codeChallenge').value = state.codeChallenge;
    }

    function clientId() { return document.getElementById('clientId').value; }
    function redirectUri() { return document.getElementById('redirectUri').value; }

    async function doAuthRequest() {
        const gen = ++fetchGen;
        state.loading = true;
        render();

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: clientId(),
            redirect_uri: redirectUri(),
            scope: state.selectedScopes.join(' '),
            code_challenge: state.codeChallenge,
            code_challenge_method: state.challengeMethod,
        });

        try {
            const res = await fetch('/authorize?' + params.toString(), {redirect: 'follow'});
            if (gen !== fetchGen) return;
            const loc = new URL(res.url);
            state.authResponse = {
                location: res.url,
                code: loc.searchParams.get('code'),
            };
        } catch (e) {
            if (gen !== fetchGen) return;
            state.authResponse = null;
        }

        state.loading = false;
        state.step = 1;
        state.maxStep = Math.max(state.maxStep, 1);
        render();
    }

    async function doTokenRequest() {
        const gen = ++fetchGen;
        state.loading = true;
        render();

        const code = state.authResponse ? state.authResponse.code : null;
        const body = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: redirectUri(),
            client_id: clientId(),
            code_verifier: state.codeVerifier,
        });
        const headers = {'Content-Type': 'application/x-www-form-urlencoded'};

        try {
            const res = await fetch('/token', {method: 'POST', headers, body: body.toString()});
            if (gen !== fetchGen) return;
            const data = await res.json();
            state.tokenResponse = {status: res.status, data};
        } catch (e) {
            if (gen !== fetchGen) return;
            state.tokenResponse = null;
        }

        state.loading = false;
        state.step = 3;
        state.maxStep = Math.max(state.maxStep, 3);
        render();
    }

    // ---- Step generators ----

    function buildSteps() {
        const cid = clientId(), ruri = redirectUri();
        const scopes = state.selectedScopes.join(' ');
        const code = state.authResponse ? state.authResponse.code : '';

        const authParams = {
            response_type: 'code',
            client_id: cid,
            redirect_uri: ruri,
            scope: scopes,
            code_challenge: state.codeChallenge || '<code_challenge>',
            code_challenge_method: state.challengeMethod,
        };

        const tokenData = state.tokenResponse ? state.tokenResponse.data : null;
        const tokenStatus = state.tokenResponse ? String(state.tokenResponse.status) : '200';
        const tokenBadgeClass = state.tokenResponse && state.tokenResponse.status !== 200 ? 'badge-local' : 'badge-get';

        return [{
            badge: 'GET',
            badgeClass: 'badge-get',
            title: 'Authorization request',
            path: '/authorize',
            desc: 'The client generates a random code_verifier, derives the code_challenge from it, then sends the challenge to the authorization endpoint. The verifier never leaves the client at this step.',
            http: 'GET /authorize HTTP/1.1\n' +
                'Host: ' + window.location.host + '\n\n' +
                Object.entries(authParams).map(([k, v], i) => (i === 0 ? '  ' : '  &') + k + '=' + v).join('\n'),
        }, {
            badge: '302',
            badgeClass: 'badge-local',
            title: 'Authorization response',
            path: '',
            desc: 'The server stores the code_challenge alongside the authorization code, then redirects back to the client with the code.',
            http: state.authResponse ? 'HTTP/1.1 302 Found\nLocation: ' + state.authResponse.location : null,
        }, {
            badge: 'POST',
            badgeClass: 'badge-post',
            title: 'Token request',
            path: '/token',
            desc: 'The client sends the authorization code together with the original code_verifier. The server verifies that the verifier matches the stored challenge before issuing the access token.',
            http: 'POST /token HTTP/1.1\n' +
                'Host: ' + window.location.host + '\n' +
                'Content-Type: application/x-www-form-urlencoded\n\n' +
                '  grant_type=authorization_code\n' +
                '  &code=' + (code || '<code>') + '\n' +
                '  &redirect_uri=' + ruri + '\n' +
                '  &client_id=' + cid + '\n' +
                '  &code_verifier=' + (state.codeVerifier || '<code_verifier>'),
        }, {
            badge: tokenStatus,
            badgeClass: tokenBadgeClass,
            title: 'Token response',
            path: 'application/json',
            desc: tokenData && tokenData.error
                ? `Token request failed: ${tokenData.error}${tokenData.error_description ? ' — ' + tokenData.error_description : ''}.`
                : 'The server verified the code_verifier against the stored code_challenge and issued an access token.',
            http: tokenData
                ? `HTTP/1.1 ${tokenStatus} ${tokenStatus === '200' ? 'OK' : 'Bad Request'}\n` +
                  'Content-Type: application/json;charset=UTF-8\n' +
                  'Cache-Control: no-store\n' +
                  'Pragma: no-cache\n\n' +
                  JSON.stringify(tokenData, null, 2)
                : null,
        }];
    }

    function renderScopes() {
        const el = document.getElementById('scopeList');
        el.innerHTML = '';
        state.scopes.forEach(s => {
            const on = state.selectedScopes.includes(s);
            const row = document.createElement('div');
            row.className = 'scope-item' + (on ? ' on' : '');
            row.innerHTML = `<div class="box"></div><span>${s}</span>`;
            row.onclick = () => {
                state.selectedScopes = state.selectedScopes.includes(s)
                    ? state.selectedScopes.filter(x => x !== s)
                    : [...state.selectedScopes, s];
                render();
            };
            el.appendChild(row);
        });
    }

    function esc(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function httpHtml(raw) {
        let firstLine = true, inBody = false;
        return raw.split('\n').map(line => {
            if (firstLine) { firstLine = false; return `<span class="http-line1">${esc(line)}</span>`; }
            if (line === '') { inBody = true; return ''; }
            if (inBody) {
                const tsMatch = line.match(/^(\s*"(?:iat|exp|nbf)":\s*)(\d+)(,?)$/);
                if (tsMatch) {
                    const date = new Date(parseInt(tsMatch[2], 10) * 1000).toLocaleString();
                    return `<span class="http-body">${esc(tsMatch[1])}<span class="ts-hint" data-tooltip="${date}">${tsMatch[2]}</span>${esc(tsMatch[3])}</span>`;
                }
                return `<span class="http-body">${esc(line)}</span>`;
            }
            const ci = line.indexOf(':');
            if (ci > 0) return `<span class="http-hdr-key">${esc(line.slice(0, ci + 1))}</span><span class="http-hdr-val">${esc(line.slice(ci + 1))}</span>`;
            return esc(line);
        }).join('\n');
    }

    let STEPS = [];
    const rawTexts = {};

    function renderSteps() {
        STEPS = buildSteps();
        const el = document.getElementById('steps');
        el.innerHTML = '';
        STEPS.forEach((s, i) => {
            const wrap = document.createElement('div');
            let cls = 'step';
            if (i < state.step) cls += ' done';
            if (i === state.step) cls += ' active';
            wrap.className = cls;

            let detail = '';
            if (i <= state.maxStep && s.http) {
                rawTexts[i] = s.http;
                detail += `<div class="kv-block"><button class="copy-btn" data-step="${i}">Copy</button><pre class="http-raw">${httpHtml(s.http)}</pre></div>`;
            }

            wrap.innerHTML = `
        <div class="step-node">${i + 1}</div>
        <div class="step-card">
          <div class="step-top">
            <span class="step-badge ${s.badgeClass}">${s.badge}</span>
            <span class="step-title">${s.title}</span>
            <span class="step-path">${s.path}</span>
          </div>
          <div class="step-desc">${s.desc}</div>
          <div class="step-detail">${detail}</div>
        </div>`;
            wrap.onclick = () => {
                if (window.getSelection && window.getSelection().toString()) return;
                state.step = i;
                render();
            };
            el.appendChild(wrap);
        });

        const fill = document.getElementById('railFill');
        if (state.step < 0) {
            fill.style.height = '0px';
        } else {
            const nodes = el.querySelectorAll('.step-node');
            const container = document.getElementById('rail').getBoundingClientRect();
            const target = nodes[state.step].getBoundingClientRect();
            fill.style.height = Math.max(0, (target.top - container.top) + 13) + 'px';
        }

        const nextBtn = document.getElementById('nextBtn');
        nextBtn.textContent = state.loading ? 'Calling…' : 'Step →';
        nextBtn.disabled = state.loading || state.step >= STEPS.length - 1;
    }

    function render() {
        renderScopes();
        renderSteps();
    }

    function initForm() {
        const c = window.__CLIENT__ || {};
        document.getElementById('clientName').value = c.client_name || '';
        document.getElementById('clientId').value = c.client_id || '';
        document.getElementById('redirectUri').value = (c.redirect_uris || [])[0] || '';
        document.getElementById('authMethod').value = c.token_endpoint_auth_method || 'none';
        document.getElementById('authMethodHint').textContent = 'Public client — no client secret. PKCE protects the authorization code exchange.';

        state.scopes = Array.isArray(c.scopes) ? c.scopes : [];
        state.selectedScopes = [...state.scopes];

        state.challengeMethod = document.getElementById('challengeMethod').value;
        document.getElementById('challengeMethodHint').textContent = CHALLENGE_METHOD_HINTS[state.challengeMethod] || '';

        refreshPKCE().then(() => render());
    }

    // ---- Event handlers ----

    document.getElementById('nextBtn').onclick = async () => {
        if (state.step === 0) {
            await doAuthRequest();
        } else if (state.step === 2) {
            await doTokenRequest();
        } else if (state.step < STEPS.length - 1) {
            state.step++;
            state.maxStep = Math.max(state.maxStep, state.step);
            render();
        }
    };

    document.getElementById('resetBtn').onclick = () => {
        fetchGen++;
        state.step = -1;
        state.maxStep = -1;
        state.loading = false;
        state.authResponse = null;
        state.tokenResponse = null;
        refreshPKCE().then(() => render());
    };

    document.getElementById('challengeMethod').addEventListener('change', () => {
        state.challengeMethod = document.getElementById('challengeMethod').value;
        document.getElementById('challengeMethodHint').textContent = CHALLENGE_METHOD_HINTS[state.challengeMethod] || '';
        refreshPKCE().then(() => render());
    });

    // ---- Copy button ----
    document.addEventListener('click', e => {
        const btn = e.target.closest('.copy-btn');
        if (!btn) return;
        const text = rawTexts[btn.dataset.step];
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => {
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
        });
    });

    // ---- Timestamp tooltip ----
    const tooltip = document.getElementById('ts-tooltip');
    document.addEventListener('mouseover', e => {
        const el = e.target.closest('[data-tooltip]');
        if (!el) return;
        tooltip.textContent = el.dataset.tooltip;
        tooltip.classList.add('show');
    });
    document.addEventListener('mouseout', e => {
        if (!e.target.closest('[data-tooltip]')) return;
        tooltip.classList.remove('show');
    });
    document.addEventListener('mousemove', e => {
        tooltip.style.left = (e.clientX + 12) + 'px';
        tooltip.style.top = (e.clientY - 28) + 'px';
    });

    initForm();
})();
