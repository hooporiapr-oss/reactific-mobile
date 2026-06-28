// cognitive-sync.js — Reactific Score Sync
// Used by the premium STROBE™ Arena 5x10 competition pages.
// Free 5x5 practice pages should not load this file.

(function () {
  var API_URL = window.REACTIFIC_API_URL || 'https://api.reactificgaming.com';

  var TOKEN_KEY = 'reactific-token';
  var USER_KEY = 'reactific-user';

  // ── Auth helpers ──────────────────────────────────────
  function getToken() {
    return localStorage.getItem(TOKEN_KEY);
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(USER_KEY));
    } catch (e) {
      return null;
    }
  }

  function setAuth(token, user) {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user || {}));
    window.dispatchEvent(new CustomEvent('reactific-user-updated', { detail: user || {} }));
  }

  function clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    window.dispatchEvent(new CustomEvent('reactific-user-updated', { detail: null }));
  }

  function isLoggedIn() {
    return !!getToken();
  }

  function isSubscribed() {
    var u = getUser();
    return !!u && u.subscription_status === 'active';
  }

  function getDisplayName(user) {
    user = user || getUser() || {};
    return user.display_name || user.username || 'Player';
  }

  function getSchoolOrg(user) {
    user = user || getUser() || {};
    return user.school_org || user.organization || user.school || 'Reactific Arena';
  }

  // ── API calls ─────────────────────────────────────────
  function api(method, path, body) {
    var opts = {
      method: method,
      headers: { 'Content-Type': 'application/json' }
    };

    var token = getToken();
    if (token) opts.headers.Authorization = 'Bearer ' + token;
    if (body) opts.body = JSON.stringify(body);

    return fetch(API_URL + path, opts).then(function (r) {
      if (r.status === 401) clearAuth();

      return r.json().then(function (data) {
        if (!r.ok) {
          var err = new Error(data.error || 'API error');
          err.status = r.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  }

  // ── Public Auth API ───────────────────────────────────

  window.reactificRegister = function (email, username, password, profile) {
    profile = profile || {};

    return api('POST', '/api/auth/register', {
      email: email,
      username: username,
      password: password,
      display_name: profile.display_name,
      school_org: profile.school_org
    }).then(function (data) {
      if (data.token) setAuth(data.token, data.user);
      return data;
    });
  };

  window.reactificLogin = function (email, password) {
    return api('POST', '/api/auth/login', {
      email: email,
      password: password
    }).then(function (data) {
      if (data.token) setAuth(data.token, data.user);
      return data;
    });
  };

  window.reactificLogout = function () {
    clearAuth();
  };

  window.reactificGetUser = function () {
    return getUser();
  };

  window.reactificGetDisplayName = function () {
    return getDisplayName();
  };

  window.reactificGetSchoolOrg = function () {
    return getSchoolOrg();
  };

  window.reactificIsLoggedIn = function () {
    return isLoggedIn();
  };

  window.reactificIsSubscribed = function () {
    return isSubscribed();
  };

  // Refresh user data from server
  window.reactificRefreshUser = function () {
    if (!isLoggedIn()) return Promise.resolve(null);

    return api('GET', '/api/auth/me').then(function (data) {
      if (data.user) {
        setAuth(getToken(), data.user);
        return data.user;
      }
      return null;
    });
  };

  // Update visible player identity on arena pages.
  // Use any of these optional IDs in the competition header:
  //   playerName, studentName, arenaPlayerName
  //   schoolOrg, organizationName, arenaSchoolOrg
  window.reactificRenderPlayerHeader = function () {
    var user = getUser() || {};
    var name = getDisplayName(user);
    var school = getSchoolOrg(user);

    ['playerName', 'studentName', 'arenaPlayerName'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.textContent = name;
    });

    ['schoolOrg', 'organizationName', 'arenaSchoolOrg'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.textContent = school;
    });

    return { name: name, school_org: school };
  };

  window.addEventListener('reactific-user-updated', function () {
    if (window.reactificRenderPlayerHeader) window.reactificRenderPlayerHeader();
  });

  document.addEventListener('DOMContentLoaded', function () {
    if (window.reactificRenderPlayerHeader) window.reactificRenderPlayerHeader();
  });

  // ── Score sync — called by STROBE Arena ───────────────

  window.syncCognitiveScore = function (speed, level, score, streak, tier, extra) {
    extra = extra || {};

    if (!isLoggedIn()) {
      console.log('[reactific] not logged in — score not posted');
      window.dispatchEvent(new CustomEvent('reactific-score-skipped', {
        detail: { reason: 'not_logged_in' }
      }));
      return Promise.resolve({ skipped: true, reason: 'not_logged_in' });
    }

    var court = window.REACTIFIC_COURT || 'full';

    if (court === 'full' && !isSubscribed()) {
      console.log('[reactific] STROBE Arena requires subscription');
      window.dispatchEvent(new CustomEvent('reactific-score-skipped', {
        detail: { reason: 'subscription_required' }
      }));
      return Promise.resolve({ skipped: true, reason: 'subscription_required' });
    }

    return api('POST', '/api/scores', {
      court: court,
      speed: speed,
      level: level,
      score: score,
      streak: streak || 0,
      tier: tier || 1,
      targets_found: extra.targets_found || level,
      time_remaining_ms: extra.time_remaining_ms || 0,
      challenge_code: extra.challenge_code || window.REACTIFIC_CHALLENGE_CODE || 'daily',
      challenge_name: extra.challenge_name || window.REACTIFIC_CHALLENGE_NAME || 'Daily Challenge'
    }).then(function (data) {
      console.log('[reactific] score posted — rank #' + data.rank);

      window.dispatchEvent(new CustomEvent('reactific-score-posted', { detail: data }));
      window.dispatchEvent(new CustomEvent('reactific-rank', { detail: data }));

      return data;
    }).catch(function (err) {
      console.error('[reactific] sync failed:', err);

      window.dispatchEvent(new CustomEvent('reactific-score-error', {
        detail: { error: err.message || String(err), status: err.status || null }
      }));

      return { error: true, message: err.message || String(err), status: err.status || null };
    });
  };

  // ── Leaderboard ───────────────────────────────────────

  window.reactificLeaderboard = function (period, speed, limit) {
    period = period || 'daily';
    speed = speed || 'slow';
    limit = limit || 50;

    return api(
      'GET',
      '/api/leaderboard/' +
        encodeURIComponent(period) +
        '?speed=' +
        encodeURIComponent(speed) +
        '&limit=' +
        encodeURIComponent(limit)
    );
  };

  window.reactificMyRank = function (speed) {
    if (!isLoggedIn()) return Promise.resolve({ rank: null, score: 0 });

    return api(
      'GET',
      '/api/leaderboard/myrank?speed=' + encodeURIComponent(speed || 'slow')
    );
  };

  // ── Stripe ────────────────────────────────────────────

  window.reactificSubscribe = function () {
    if (!isLoggedIn()) return Promise.reject(new Error('Login required'));

    return api('POST', '/api/stripe/checkout').then(function (data) {
      if (data.url) window.location.href = data.url;
      return data;
    });
  };

  window.reactificManageSubscription = function () {
    if (!isLoggedIn()) return Promise.reject(new Error('Login required'));

    return api('POST', '/api/stripe/portal').then(function (data) {
      if (data.url) window.location.href = data.url;
      return data;
    });
  };
})();
