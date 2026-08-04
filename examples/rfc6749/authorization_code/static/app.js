(function () {
    const state = {
        step: -1,    // currently highlighted step (for viewing)
        maxStep: -1, // highest step legitimately reached through the flow
        loading: false, authMethod: 'none', scopes: [], authResponse: null,  // { location, code, callbackState } populated after real /authorize call
        tokenResponse: null, // { status, data } populated after real /token call
    };
    let fetchGen = 0; // incremented on reset to discard in-flight results

    const RESPONSE_TYPE_HINTS = {
        code: 'The server returns a short-lived authorization code. The client exchanges it for tokens at the token endpoint via a back-channel request (RFC 6749 §4.1).',
        token: 'The server returns an access token directly in the redirect URI fragment. No token endpoint exchange — suitable only for legacy implicit flow (RFC 6749 §4.2).',
    };

    const AUTH_METHOD_HINTS = {
        client_secret_basic: 'Confidential client. Credentials are sent as an HTTP Basic Authorization header on the token request (RFC 6749 §2.3.1).',
        client_secret_post: 'Confidential client. client_id and client_secret are sent as POST body parameters on the token request.',
        none: 'Public client — no client secret. The client cannot securely store credentials (e.g. SPA, native app). Use PKCE to protect the code exchange.',
    };

    function clientId() {
        return document.getElementById('clientId').value;
    }

    function redirectUri() {
        return document.getElementById('redirectUri').value;
    }

    function allowedScopes() {
        return state.scopes;
    }

    function randToken(len) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        let out = '';
        for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
        return out;
    }

    let tokenState = null;

    function getTokenState() {
        if (!tokenState) tokenState = {state: randToken(16)};
        return tokenState;
    }

    async function doAuthRequest() {
        const gen = ++fetchGen;
        state.loading = true;
        render();

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: clientId(),
            redirect_uri: redirectUri(),
            scope: allowedScopes().join(' '),
            state: getTokenState().state,
        });

        try {
            const res = await fetch('/authorize?' + params.toString(), {redirect: 'follow'});
            if (gen !== fetchGen) return;
            const loc = new URL(res.url);
            state.authResponse = {
                location: res.url, code: loc.searchParams.get('code'), callbackState: loc.searchParams.get('state'),
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
            grant_type: 'authorization_code', code, redirect_uri: redirectUri(), client_id: clientId()
        });
        const headers = {'Content-Type': 'application/x-www-form-urlencoded'};

        if (state.authMethod === 'client_secret_basic') {
            headers['Authorization'] = 'Basic ' + btoa(clientId() + ':' + (window.__CLIENT_SECRET__ || ''));
        } else if (state.authMethod === 'client_secret_post') {
            body.set('client_secret', window.__CLIENT_SECRET__ || '');
        }

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
        const cid = clientId(), ruri = redirectUri(), scopes = allowedScopes().join(' ');
        const p = getTokenState();
        const realAuth = state.authResponse;
        const code = realAuth ? realAuth.code : '';

        const authParams = Object.entries({
            response_type: 'code',
            client_id: cid,
            redirect_uri: ruri,
            scope: scopes,
            state: p.state,
        });

        const tokenBody = {grant_type: 'authorization_code', code, redirect_uri: ruri, client_id: cid};
        let authHeader = '';
        switch (state.authMethod) {
            case 'client_secret_basic':
                authHeader = '\nAuthorization: Basic <base64(' + cid + ':client_secret)>';
                break;
            case 'client_secret_post':
                tokenBody.client_secret = window.__CLIENT_SECRET__;
                break;
        }

        const tokenData = state.tokenResponse ? state.tokenResponse.data : null;
        const tokenStatus = state.tokenResponse ? String(state.tokenResponse.status) : '200';
        const tokenBadgeClass = state.tokenResponse && state.tokenResponse.status !== 200 ? 'badge-local' : 'badge-get';

        return [{
            badge: 'GET',
            badgeClass: 'badge-get',
            title: 'Authorization request',
            path: '/authorize',
            desc: 'Browser redirects to the authorization endpoint. The server authenticates the user and asks for consent.',
            http: 'GET /authorize HTTP/1.1\n' + 'Host: ' + window.location.host + '\n\n' + authParams.map(([k, v], i) => (i === 0 ? '  ' : '  &') + k + '=' + v).join('\n'),
        }, {
            badge: '302',
            badgeClass: 'badge-local',
            title: 'Authorization response',
            path: '',
            desc: 'The server redirects back to the client with a short-lived, single-use authorization code.',
            http: realAuth ? 'HTTP/1.1 302 Found\nLocation: ' + realAuth.location : null,
        }, {
            badge: 'POST',
            badgeClass: 'badge-post',
            title: 'Token request',
            path: '/token',
            desc: 'A back-channel request trades the code for tokens. ' + AUTH_METHOD_HINTS[state.authMethod],
            http: 'POST /token HTTP/1.1\n' + 'Host: ' + window.location.host + '\n' +'Content-Type: application/x-www-form-urlencoded' + authHeader + '\n\n' + Object.entries(tokenBody).map(([k, v], i) => (i === 0 ? '  ' : '  &') + k + '=' + v).join('\n'),
        }, {
            badge: tokenStatus,
            badgeClass: tokenBadgeClass,
            title: 'Token response',
            path: 'application/json',
            desc: tokenData && tokenData.error ? `Token request failed: ${tokenData.error}${tokenData.error_description ? ' — ' + tokenData.error_description : ''}.` : 'The server returns an access token' + (tokenData && tokenData.refresh_token ? ' and a refresh token.' : '.'),
            http: tokenData ? `HTTP/1.1 ${tokenStatus} ${tokenStatus === '200' ? 'OK' : 'Bad Request'}\n` + 'Content-Type: application/json;charset=UTF-8\n' + 'Cache-Control: no-store\n' + 'Pragma: no-cache\n\n' + JSON.stringify(tokenData, null, 2) : null,
        },];
    }

    // ---- Rendering ----
    function renderScopes() {
        const el = document.getElementById('scopeList');
        el.innerHTML = '';
        state.scopes.forEach(s => {
            const row = document.createElement('div');
            row.className = 'scope-item on';
            row.innerHTML = `<div class="box"></div><span>${s}</span>`;
            el.appendChild(row);
        });
    }

    function esc(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    function httpHtml(raw) {
        let firstLine = true, inBody = false;
        return raw.split('\n').map(line => {
            if (firstLine) {
                firstLine = false;
                return `<span class="http-line1">${esc(line)}</span>`;
            }
            if (line === '') {
                inBody = true;
                return '';
            }
            if (inBody) return `<span class="http-body">${esc(line)}</span>`;
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

    function loadClient() {
        const c = window.__CLIENT__ || {};
        document.getElementById('clientName').value = c.client_name || '';
        document.getElementById('clientId').value = c.client_id || '';
        document.getElementById('redirectUri').value = (c.redirect_uris || [])[0] || '';
        const responseTypes = c.response_types || [];
        document.getElementById('responseType').value = responseTypes.join(', ');
        document.getElementById('responseTypeHint').textContent = responseTypes.map(rt => RESPONSE_TYPE_HINTS[rt] || rt).join(' ');
        const method = c.token_endpoint_auth_method || 'none';
        document.getElementById('authMethod').value = method;
        document.getElementById('authMethodHint').textContent = AUTH_METHOD_HINTS[method] || '';
        state.authMethod = method;

        state.scopes = Array.isArray(c.scopes) ? c.scopes : [];

        render();
    }

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
        fetchGen++; // discard any in-flight fetch result
        state.step = -1;
        state.maxStep = -1;
        state.loading = false;
        tokenState = null;
        state.authResponse = null;
        state.tokenResponse = null;
        render();
    };
    document.getElementById('clientId').addEventListener('input', () => render());

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

    loadClient();
})();
