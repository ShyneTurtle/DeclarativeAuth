// Client side of the WebAuthn passkey ceremonies: registering a new passkey
// from the account page, and logging in with one from the login page. The
// server (see internal/web/webauthn.go) only ever speaks the standard
// WebAuthn JSON shapes -- this file's job is converting between those
// (base64url strings) and the ArrayBuffers navigator.credentials expects,
// and driving the two-step start/finish exchange with fetch.
window.DeclarativeAuthPasskeys = (function () {
  "use strict";

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  function base64urlToBuffer(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // decodeCreationOptions/decodeRequestOptions turn the server's JSON
  // (base64url strings for challenge/id fields) into the ArrayBuffer-based
  // shape navigator.credentials.create()/get() require.
  function decodeCreationOptions(publicKey) {
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    publicKey.user.id = base64urlToBuffer(publicKey.user.id);
    (publicKey.excludeCredentials || []).forEach(function (c) {
      c.id = base64urlToBuffer(c.id);
    });
    return publicKey;
  }

  function decodeRequestOptions(publicKey) {
    publicKey.challenge = base64urlToBuffer(publicKey.challenge);
    (publicKey.allowCredentials || []).forEach(function (c) {
      c.id = base64urlToBuffer(c.id);
    });
    return publicKey;
  }

  // encodeCredential converts the browser's PublicKeyCredential result back
  // into the plain JSON object the server expects, matching the shape
  // produced natively by credential.toJSON() where available.
  function encodeCredential(credential) {
    if (typeof credential.toJSON === "function") {
      return credential.toJSON();
    }
    var response = credential.response;
    var out = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
    };
    if (credential.authenticatorAttachment) {
      out.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (response.attestationObject) {
      out.response = {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        attestationObject: bufferToBase64url(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : [],
      };
    } else {
      out.response = {
        clientDataJSON: bufferToBase64url(response.clientDataJSON),
        authenticatorData: bufferToBase64url(response.authenticatorData),
        signature: bufferToBase64url(response.signature),
        userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
      };
    }
    return out;
  }

  function setStatus(el, message, isError) {
    if (!el) return;
    el.textContent = message || "";
    el.className = isError ? "error" : "";
  }

  function register(csrfToken, statusEl, onDone) {
    setStatus(statusEl, "Follow your browser's prompt to create a passkey…", false);
    fetch("/webauthn/register/start", { method: "POST", headers: { "X-CSRF-Token": csrfToken } })
      .then(function (resp) {
        if (!resp.ok) throw new Error("could not start passkey registration");
        return resp.json();
      })
      .then(function (options) {
        return navigator.credentials.create({ publicKey: decodeCreationOptions(options.publicKey) });
      })
      .then(function (credential) {
        var name = (window.prompt("Name this passkey (e.g. \"MacBook Touch ID\")", "Passkey") || "Passkey").slice(0, 100);
        return fetch("/webauthn/register/finish?name=" + encodeURIComponent(name), {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
          body: JSON.stringify(encodeCredential(credential)),
        });
      })
      .then(function (resp) {
        if (!resp.ok) throw new Error("could not save the new passkey");
        setStatus(statusEl, "Passkey added.", false);
        if (onDone) onDone();
      })
      .catch(function (err) {
        setStatus(statusEl, err.message || "Adding the passkey failed.", true);
      });
  }

  function login(returnTo, statusEl) {
    setStatus(statusEl, "Follow your browser's prompt to use a passkey…", false);
    fetch("/webauthn/login/start", { method: "POST" })
      .then(function (resp) {
        if (!resp.ok) throw new Error("could not start passkey login");
        return resp.json();
      })
      .then(function (options) {
        return navigator.credentials.get({ publicKey: decodeRequestOptions(options.publicKey) });
      })
      .then(function (credential) {
        return fetch("/webauthn/login/finish?return_to=" + encodeURIComponent(returnTo || "/"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(encodeCredential(credential)),
        });
      })
      .then(function (resp) {
        if (!resp.ok) throw new Error("Passkey login failed.");
        return resp.json();
      })
      .then(function (result) {
        window.location.href = result.redirect || "/";
      })
      .catch(function (err) {
        setStatus(statusEl, err.message || "Passkey login failed.", true);
      });
  }

  function initLoginButton(button, statusEl, returnTo) {
    if (!button) return;
    if (!supported()) return;
    button.hidden = false;
    button.addEventListener("click", function () {
      login(returnTo, statusEl);
    });
  }

  function initRegisterButton(button, statusEl, csrfToken) {
    if (!button) return;
    if (!supported()) {
      setStatus(statusEl, "This browser does not support passkeys.", true);
      return;
    }
    button.hidden = false;
    button.addEventListener("click", function () {
      register(csrfToken, statusEl, function () {
        window.location.reload();
      });
    });
  }

  return { initLoginButton: initLoginButton, initRegisterButton: initRegisterButton };
})();
