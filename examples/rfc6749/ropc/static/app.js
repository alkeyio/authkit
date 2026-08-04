(function () {
    const state = {
        step: -1,    // currently highlighted step (for viewing)
        maxStep: -1, // highest step legitimately reached through the flow
        loading: false,
        authMethod: 'client_secret_basic',
        scopes: [],         // all available scopes from client config
        selectedScopes: [], // scopes currently toggled on
        tokenResponse: null, // { status, data } populated after real /token call
    };
    let fetchGen = 0; // incremented on reset to discard in-flight results

    const AUTH_METHOD_HINTS = {
        none: 'Public client — no client secret. The client_id is sent as a POST body parameter.',
        client_secret_basic: 'Confidential client. Credentials are sent as an HTTP Basic Authorization header on the token request (RFC 6749 §2.3.1).',
        client_secret_post: 'Confidential client. client_id and client_secret are sent as POST body parameters on the token request.',
    };

    function clientId() {
        return document.getElementById('clientId').value;
    }

    function clientSecret() {
        return document.getElementById('clientSecret').value;
    }

    function username() {
        return document.getElementById('username').value;
    }

    function password() {
        return document.getElementById('password').value;
    }

    async function doTokenRequest() {
        const gen = ++fetchGen;
        state.loading = true;
        render();

        const body = new URLSearchParams({
            grant_type: 'password',
            username: username(),
            password: password(),
        });
        if (state.selectedScopes.length > 0) {
            body.set('scope', state.selectedScopes.join(' '));
        }
        const headers = {'Content-Type': 'application/x-www-form-urlencoded'};

        if (state.authMethod === 'client_secret_basic') {
            headers['Authorization'] = 'Basic ' + btoa(clientId() + ':' + clientSecret());
        } else if (state.authMethod === 'client_secret_post') {
            body.set('client_id', clientId());
            body.set('client_secret', clientSecret());
        } else {
            body.set('client_id', clientId());
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
        state.step = 1;
        state.maxStep = Math.max(state.maxStep, 1);
        render();
    }

    // ---- Step generators ----
    function buildSteps() {
        const cid = clientId();
        const secret = clientSecret();
        const uname = username();
        const scopes = state.selectedScopes.join(' ');

        const tokenBody = {grant_type: 'password', username: uname, password: '***'};
        if (scopes) tokenBody.scope = scopes;

        let authHeader = '';
        switch (state.authMethod) {
            case 'client_secret_basic':
                authHeader = '\nAuthorization: Basic ' + btoa(cid + ':' + secret);
                break;
            case 'client_secret_post':
                tokenBody.client_id = cid;
                tokenBody.client_secret = secret;
                break;
            default:
                tokenBody.client_id = cid;
                break;
        }

        const tokenData = state.tokenResponse ? state.tokenResponse.data : null;
        const tokenStatus = state.tokenResponse ? String(state.tokenResponse.status) : '200';
        const tokenBadgeClass = state.tokenResponse && state.tokenResponse.status !== 200 ? 'badge-local' : 'badge-get';

        return [{
            badge: 'POST',
            badgeClass: 'badge-post',
            title: 'Token request',
            path: '/token',
            desc: 'The client sends the resource owner\'s credentials directly to the token endpoint. ' + (AUTH_METHOD_HINTS[state.authMethod] || ''),
            http: 'POST /token HTTP/1.1\n' + 'Host: ' + window.location.host + '\n' + 'Content-Type: application/x-www-form-urlencoded' + authHeader + '\n\n' + Object.entries(tokenBody).map(([k, v], i) => (i === 0 ? '  ' : '  &') + k + '=' + v).join('\n'),
        }, {
            badge: tokenStatus,
            badgeClass: tokenBadgeClass,
            title: 'Token response',
            path: 'application/json',
            desc: tokenData && tokenData.error
                ? `Token request failed: ${tokenData.error}${tokenData.error_description ? ' — ' + tokenData.error_description : ''}.`
                : 'The server authenticates both the client and the user, then returns an access token.',
            http: tokenData ? `HTTP/1.1 ${tokenStatus} ${tokenStatus === '200' ? 'OK' : 'Bad Request'}\n` + 'Content-Type: application/json;charset=UTF-8\n' + 'Cache-Control: no-store\n' + 'Pragma: no-cache\n\n' + JSON.stringify(tokenData, null, 2) : null,
        }];
    }

    // ---- Rendering ----
    function renderScopes() {
        const el = document.getElementById('scopeList');
        el.innerHTML = '';
        state.scopes.forEach(s => {
            const on = state.selectedScopes.includes(s);
            const row = document.createElement('div');
            row.className = 'scope-item' + (on ? ' on' : '');
            row.innerHTML = `<div class="box"></div><span>${s}</span>`;
            row.onclick = () => {
                if (state.selectedScopes.includes(s)) {
                    state.selectedScopes = state.selectedScopes.filter(x => x !== s);
                } else {
                    state.selectedScopes = [...state.selectedScopes, s];
                }
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
        document.getElementById('clientSecret').value = c.client_secret || '';
        const method = c.token_endpoint_auth_method || 'client_secret_basic';
        document.getElementById('authMethod').value = method;
        document.getElementById('authMethodHint').textContent = AUTH_METHOD_HINTS[method] || '';
        state.authMethod = method;

        state.scopes = Array.isArray(c.scopes) ? c.scopes : [];
        state.selectedScopes = [...state.scopes];

        const u = window.__USER__ || {};
        document.getElementById('username').value = u.username || '';
        document.getElementById('password').value = u.password || '';

        render();
    }

    document.getElementById('nextBtn').onclick = async () => {
        if (state.step === 0) {
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
        state.tokenResponse = null;
        render();
    };

    ['clientId', 'clientSecret', 'username', 'password'].forEach(id => {
        document.getElementById(id).addEventListener('input', () => render());
    });
    document.getElementById('authMethod').addEventListener('change', () => {
        state.authMethod = document.getElementById('authMethod').value;
        document.getElementById('authMethodHint').textContent = AUTH_METHOD_HINTS[state.authMethod] || '';
        render();
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

    loadClient();
})();
