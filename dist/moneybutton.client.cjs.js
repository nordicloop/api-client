'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var Window = _interopDefault(require('window'));
var localStorage = _interopDefault(require('localstorage-memory'));
var jsonApi = require('@moneybutton/json-api');
var fetch = _interopDefault(require('isomorphic-fetch'));
var moment = _interopDefault(require('moment'));
var queryString = _interopDefault(require('query-string'));
var uuid = _interopDefault(require('uuid'));
var sha256 = _interopDefault(require('fast-sha256'));

/**
 * Authentication API error.
 */
class AuthError {
  /**
   * @param {string} title - Error title.
   * @param {string} detail - Error detail.
   */
  constructor(title, detail) {
    this.title = title;
    this.detail = detail;
    this.message = detail !== undefined ? detail : title;
  }

}

function _defineProperty(obj, key, value) {
  if (key in obj) {
    Object.defineProperty(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }

  return obj;
}

function ownKeys(object, enumerableOnly) {
  var keys = Object.keys(object);

  if (Object.getOwnPropertySymbols) {
    var symbols = Object.getOwnPropertySymbols(object);
    if (enumerableOnly) symbols = symbols.filter(function (sym) {
      return Object.getOwnPropertyDescriptor(object, sym).enumerable;
    });
    keys.push.apply(keys, symbols);
  }

  return keys;
}

function _objectSpread2(target) {
  for (var i = 1; i < arguments.length; i++) {
    var source = arguments[i] != null ? arguments[i] : {};

    if (i % 2) {
      ownKeys(Object(source), true).forEach(function (key) {
        _defineProperty(target, key, source[key]);
      });
    } else if (Object.getOwnPropertyDescriptors) {
      Object.defineProperties(target, Object.getOwnPropertyDescriptors(source));
    } else {
      ownKeys(Object(source)).forEach(function (key) {
        Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
      });
    }
  }

  return target;
}

function _objectWithoutPropertiesLoose(source, excluded) {
  if (source == null) return {};
  var target = {};
  var sourceKeys = Object.keys(source);
  var key, i;

  for (i = 0; i < sourceKeys.length; i++) {
    key = sourceKeys[i];
    if (excluded.indexOf(key) >= 0) continue;
    target[key] = source[key];
  }

  return target;
}

function _objectWithoutProperties(source, excluded) {
  if (source == null) return {};

  var target = _objectWithoutPropertiesLoose(source, excluded);

  var key, i;

  if (Object.getOwnPropertySymbols) {
    var sourceSymbolKeys = Object.getOwnPropertySymbols(source);

    for (i = 0; i < sourceSymbolKeys.length; i++) {
      key = sourceSymbolKeys[i];
      if (excluded.indexOf(key) >= 0) continue;
      if (!Object.prototype.propertyIsEnumerable.call(source, key)) continue;
      target[key] = source[key];
    }
  }

  return target;
}

/**
 * REST API error.
 */
class RestError {
  /**
   *
   * @param {number} status - HTTP status code.
   * @param {string} title - Error title.
   * @param {string} detail - Error detail.
   */
  constructor(status, title, detail) {
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.message = detail !== undefined ? detail : title;
  }

}

const MB_URL = 'https://www.moneybutton.com';
const LOGIN_PASSWORD_HMAC_KEY = 'yours login password';
const STORAGE_NAMESPACE = 'mb_js_client';
const OAUTH_REDIRECT_URI_KEY = [STORAGE_NAMESPACE, 'oauth_redirect_uri'].join(':');
const OAUTH_STATE_KEY = [STORAGE_NAMESPACE, 'oauth_state'].join(':');
const OAUTH_ACCESS_TOKEN_KEY = [STORAGE_NAMESPACE, 'oauth_access_token'].join(':');
const OAUTH_EXPIRATION_TIME_KEY = [STORAGE_NAMESPACE, 'oauth_expiration_time'].join(':');
const OAUTH_REFRESH_TOKEN_KEY = [STORAGE_NAMESPACE, 'oauth_refresh_token'].join(':');
const APP_REFRESH_STRATEGY = 'client_credentials';
const DEFAULT_REFRESH_STRATEGY = 'refresh_token';
const {
  UserSerializer,
  SwipePermissionSerializer,
  AuthorizedPaymentSerializer
} = jsonApi.jsonSerializers;
/**
 * @param {Storage} webStorage - Object conforming to the Storage Web API.
 * @param {Location} webLocation - Object conforming to the Location Web API.
 */

function getMoneyButtonClient(webStorage, webLocation) {
  if (!webStorage) {
    throw new Error('Missing required web storage object.');
  }

  if (!webLocation) {
    throw new Error('Missing required web location object.');
  }
  /**
   *
   */


  class MoneyButtonClient {
    /**
     * Creates an instance of Money Button for the given OAuth client.
     *
     * @param {string} clientId - OAuth client's identifier.
     * @param {string} clientSecret - OAuth client's secret.
     */
    constructor(clientId, clientSecret = null, mbUrl = MB_URL) {
      this.clientId = clientId;
      this.clientSecret = clientSecret;
      this.refreshStrategy = DEFAULT_REFRESH_STRATEGY;
      this.mbUrl = mbUrl;
      this._currentUser = null;
    }
    /**
     * Logs in the user with the given email and password.
     *
     * @param {string} email
     * @param {string} password
     * @returns {undefined}
     */


    async logIn(email, password) {
      const loginPassword = await MoneyButtonClient._computeHmac256(LOGIN_PASSWORD_HMAC_KEY, password);

      this._clearCurrentUser();

      await this._logIn(email, loginPassword);
    }
    /**
     * Get tokens to log in as an app.
     * It changes the internal state of the client.
     */


    async logInAsApp() {
      await this._doClientCredentialsGrantAccessTokenRequest('application_access:write');

      this._clearCurrentUser();

      this.refreshStrategy = APP_REFRESH_STRATEGY;
    }
    /**
     * Logs in the user with the given email and login password.
     *
     * @private
     * @param {string} email
     * @param {string} password
     * @returns {undefined}
     */


    async _logIn(email, loginPassword) {
      if (await this.isLoggedIn()) {
        await this.logOut();
      }

      await this._doResourceOwnerPasswordCredentialsGrantAccessTokenRequest(email, loginPassword, 'general_access:write');
    }

    async logError(data) {
      await this._doPostRequest('/v2/log-data', data);
    }
    /**
     * Determines whether a user is currently logged-in.
     *
     * @returns {boolean}
     */


    async isLoggedIn() {
      const accessToken = await this.getValidAccessToken();
      return accessToken !== null;
    }
    /**
     * Retrieves a valid access token for the currently logged-in user.
     * Returns null if no user is currently logged-in.
     *
     * @returns {string|null}
     */


    async getValidAccessToken() {
      let accessToken = this.getAccessToken();

      if (accessToken !== null && moment().isBefore(moment(this.getExpirationTime()))) {
        return accessToken;
      }

      if (this.refreshStrategy === APP_REFRESH_STRATEGY) {
        await this.logInAsApp();
        return this.getAccessToken();
      } else {
        const refreshToken = this.getRefreshToken();

        if (refreshToken === null) {
          return null;
        }

        accessToken = null;

        try {
          await this._doRefreshAccessTokenRequest(refreshToken);
          accessToken = this.getAccessToken();
        } catch (err) {
          if (!(err instanceof AuthError)) {
            throw err;
          }
        }

        return accessToken;
      }
    }
    /**
     * Logs out the current logged-in user, if any.
     */


    async logOut() {
      try {
        if (this.getRefreshToken()) {
          const accessToken = await this.getValidAccessToken();

          if (accessToken) {
            await fetch(`${this.mbUrl}/oauth/v1/revoke`, {
              method: 'POST',
              headers: {
                authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                refresh_token: this.getRefreshToken()
              })
            });
          }
        }
      } finally {
        this._clearCurrentUser();

        Array.from(Array(webStorage.length).keys()) // Generates a range of integers from 0 to webStorage.length
        .map(i => webStorage.key(i)).filter(key => key.startsWith('mb_wallet') || key.startsWith(STORAGE_NAMESPACE)).forEach(key => webStorage.removeItem(key));
      }
    }
    /**
     * Create email change request.
     *
     * @param {string} email
     */


    async changeEmail(email, password) {
      return this._doPutRequest('/v2/auth/email', {
        email,
        password
      });
    }
    /**
     * Resend email verification.
     *
     * @param {string} email
     */


    async resendEmailVerification(email) {
      return this._doPostRequest('/v2/auth/resend-email-verification', {
        email
      });
    }
    /**
     * Resend email change request verification.
     *
     * @param {string} userId
     */


    async resendEmailChangeRequestVerification(userId) {
      return this._doPostRequest('/v2/auth/resend-email-change-request-verification', {
        userId
      });
    }
    /**
     * Email verification.
     *
     * @param {string} accessToken
     */


    async confirmEmailVerification(accessToken) {
      const result = await this._doPostRequest('/v2/auth/confirm-email-verification', {}, {}, accessToken);

      this._clearCurrentUser();

      return result;
    }

    async createReEncryptedWallet(encryptedMnemonic, walletId) {
      const result = await this._doPostRequest('/v2/re-encrypted-wallets', {
        encryptedMnemonic,
        walletId
      });
      return result;
    }

    async getReEncryptedWallets() {
      const result = await this._doGetRequest('/v2/re-encrypted-wallets');
      return result;
    }

    async getFeatureFlags() {
      const result = await this._doGetRequest('/v2/feature-flags');
      return result;
    }
    /**
     * Retrieves the currently logged user's identity.
     *
     * @returns {object}
     */


    async getIdentity() {
      const json = await this._doGetRequest('/v1/auth/user_identity');
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'user_identities');
    }
    /**
     * Returns an object with two keys:
     * - loggedIn: a boolean indicating whether there is a currently logged-in user.
     * - user: if loggedIn is true, this is an object with the user's attributes.
     *
     * @returns {object}
     */


    async whoAmI() {
      const loggedIn = await this.isLoggedIn();

      if (!loggedIn) {
        return {
          loggedIn
        };
      }

      const currentUser = await this._getCurrentUser();
      return {
        loggedIn,
        user: currentUser
      };
    }
    /**
     * Changes the currently logged-in user's password.
     *
     * @param {string} password
     * @param {string} encryptedMnemonic
     * @param {string} xpub
     * @param {string} language
     * @returns {object}
     */


    async changePassword(password, encryptedMnemonic, xpub, language) {
      const loginPassword = await MoneyButtonClient._computeHmac256(LOGIN_PASSWORD_HMAC_KEY, password);
      const body = jsonApi.toJsonApiDataIncluding(jsonApi.toNewResourceObject('users', {
        password: loginPassword
      }), [jsonApi.toNewResourceObject('wallets', {
        encryptedMnemonic,
        xpub,
        language
      })]);
      const json = await this._doPostRequest('/v1/auth/password_change', body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'password_changes');
    }
    /**
     * Resets the currently logged-in user's password by using the access token
     * generated during the "I forgot my password" flow.
     *
     * @param {string} accessToken - auth API access token
     * @param {string} password
     * @param {string} encryptedMnemonic
     * @param {string} xpub
     * @param {boolean} forceCreate
     * @param {string} walletLanguage
     * @returns {object}
     */


    async resetPassword(accessToken, password, encryptedMnemonic, xpub, forceCreate, walletLanguage) {
      const loginPassword = await MoneyButtonClient._computeHmac256(LOGIN_PASSWORD_HMAC_KEY, password);
      const body = jsonApi.toJsonApiDataIncluding(jsonApi.toNewResourceObject('users', {
        password: loginPassword
      }), [jsonApi.toNewResourceObject('wallets', {
        encryptedMnemonic,
        xpub,
        language: walletLanguage
      })]);
      const query = forceCreate ? {
        forceCreate: 'true'
      } : {};
      const json = await this._doPostRequest('/v1/auth/password_reset', body, query, accessToken);

      this._clearCurrentUser();

      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'password_resets');
    }
    /**
     * Sends a password reset email to begin the "I forgot my password" flow.
     *
     * @param {string} email
     * @returns {object}
     */


    async sendPasswordReset(email) {
      if (await this.isLoggedIn()) {
        await this.logOut();
      }

      await this._doClientCredentialsGrantAccessTokenRequest('auth.password_reset_email:write');
      const attributes = {
        email
      };
      const body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('users', attributes));
      const json = await this._doPostRequest('/v1/auth/password_reset_email', body);
      await this.logOut();
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'password_reset_emails');
    }
    /**
     * Creates a new user account with the given email and password.
     *
     * @param {string} email
     * @param {string} password
     * @returns {object}
     */


    async signUp(name, email, password, receiveEmails, defaultCurrency, passwordAlreadySet) {
      if (await this.isLoggedIn()) {
        await this.logOut();
      }

      return this._doPostRequest('/v2/auth/signup', {
        name,
        email,
        receiveEmails,
        defaultCurrency,
        passwordAlreadySet,
        password: await MoneyButtonClient._computeHmac256(LOGIN_PASSWORD_HMAC_KEY, password)
      });
    }
    /**
     * Delete user account.
     */


    async deleteAccount(password) {
      await this._doPostRequest('/v2/auth/delete-account', {
        password
      });
      await this.logOut();
    }

    async updateRefreshToken() {
      const refreshToken = this.getRefreshToken();

      if (refreshToken && refreshToken.split('.').length === 3) {
        const {
          refreshToken: newRefreshToken
        } = await this._doPostRequest('/v1/auth/update_refresh_token', {
          refreshToken
        });
        this.setRefreshToken(newRefreshToken);
      }
    }

    async assertNewRefreshTokenVersion(onOldVersion) {
      const refreshToken = this.getRefreshToken();

      if (!refreshToken) ; else if (refreshToken.split('.').length === 3) {
        await this.logOut();
        await onOldVersion();
      }
    }
    /**
     * Creates a new user account with the given email and login password.
     *
     * @private
     * @param {string} email
     * @param {string} loginPassword
     * @returns {object}
     */


    async _signUp(email, loginPassword, name, defaultCurrency, receiveEmails, userChosenPassword) {
      if (await this.isLoggedIn()) {
        await this.logOut();
      }

      await this._doClientCredentialsGrantAccessTokenRequest('auth.signup:write');
      const attributes = {
        email,
        password: loginPassword,
        name,
        defaultCurrency,
        receiveEmails,
        userChosenPassword
      };
      const body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('users', attributes));
      const json = await this._doPostRequest('/v1/auth/signup', body);
      await this.logOut();
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'signups');
    }
    /**
     * [Browser only] Starts the authorization flow which allows third-party applications
     * to request access to user resources on their behalf. This function will
     * redirect the user's window to the Money Button's authorization flow page.
     *
     * @param {string} scope - scope to be requested to the user.
     * @param {string} redirectUri - URI where the authorization response will be handled.
     * @returns {undefined}
     */


    requestAuthorization(scope, redirectUri, state = null) {
      if (typeof scope !== 'string' || scope.length === 0) {
        throw new Error(`Invalid scope requested: ${scope}.`);
      }

      if (typeof redirectUri !== 'string' || redirectUri.length === 0) {
        throw new Error(`Invalid return URI: ${redirectUri}.`);
      }

      this._doAuthorizationCodeGrantAuthorizationRequest(redirectUri, scope, state);
    }
    /**
     * [Browser only] Finishes the authorization flow started by {@link requestAuthorization}.
     * If successful, after calling this function, the client will be able to perform requests
     * on behalf of the user as long as they are within the scope requested when starting the
     * authorization flow.
     *
     * @returns {undefined}
     */


    async handleAuthorizationResponse() {
      const {
        error,
        code,
        state
      } = this._getUrlQuery();

      const redirectUri = this._getRedirectUri();

      if (!redirectUri) {
        throw new Error('Required OAuth redirect URI not found in storage.');
      }

      await this._handleAuthorizationCodeGrantAuthorizationResponse(error, code, state, this._getState(), this._getRedirectUri());
    }

    async authorizeWithAuthFlowResponse(queryParams, expectedState, redirectUri) {
      const {
        error,
        code,
        state
      } = queryParams;
      await this._handleAuthorizationCodeGrantAuthorizationResponse(error, code, state, expectedState, redirectUri);
    }
    /**
     * See: https://tools.ietf.org/html/rfc6749#page-24.
     *
     * @private
     * @param {string} redirectUri
     * @param {string} scope
     */


    _doAuthorizationCodeGrantAuthorizationRequest(redirectUri, scope, state = null) {
      if (this.clientSecret !== null) {
        throw new Error(['Grant `authentication_code` can only be performed by ', 'a public client (that is, a client with no client secret).'].join(''));
      }

      if (state === null) {
        state = uuid.v4();
      }

      this._setRedirectUri(redirectUri);

      this._setState(state);

      const authorizationUri = [`${this.mbUrl}/oauth/v1/authorize`, queryString.stringify({
        response_type: 'code',
        client_id: this.clientId,
        redirect_uri: redirectUri,
        scope,
        state
      })].join('?');

      this._redirectToUri(authorizationUri);
    }
    /**
     * See: https://tools.ietf.org/html/rfc6749#page-26.
     *
     * @private
     */


    async _handleAuthorizationCodeGrantAuthorizationResponse(error, code, state, expectedState, redirectUri) {
      if (error !== undefined) {
        throw new AuthError('Authorization failed.', error.message);
      }

      if (code === undefined) {
        throw new Error('Missing OAuth authorization code.');
      }

      if (expectedState === null || state !== expectedState) {
        throw new Error('Invalid OAuth state.');
      }

      await this._doAuthorizationCodeGrantAccessTokenRequest(code, redirectUri);
    }
    /**
     * See: https://tools.ietf.org/html/rfc6749#page-29.
     *
     * @private
     */


    async _doAuthorizationCodeGrantAccessTokenRequest(code, redirectUri) {
      if (!redirectUri) {
        throw new Error('Required OAuth redirect URI not found.');
      }

      await this._doAccessTokenRequest({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: this.clientId
      });
    }
    /**
     * See: https://tools.ietf.org/html/rfc6749#page-37.
     *
     * @private
     */


    async _doResourceOwnerPasswordCredentialsGrantAccessTokenRequest(username, password, scope) {
      await this._doAccessTokenRequest({
        grant_type: 'password',
        username,
        password,
        scope
      }, this._buildBasicAuthHeaders());
    }
    /**
     * See: https://tools.ietf.org/html/rfc6749#page-41.
     *
     * @private
     */


    async _doClientCredentialsGrantAccessTokenRequest(scope) {
      await this._doAccessTokenRequest({
        grant_type: 'client_credentials',
        scope
      }, this._buildBasicAuthHeaders());
    }
    /**
     * @private
     * @param {string} refreshToken
     */


    async _doRefreshAccessTokenRequest(refreshToken) {
      const response = await fetch(`${this.mbUrl}/oauth/v1/auth-proxy/token`, {
        method: 'POST',
        body: JSON.stringify({
          grant_type: 'refresh_token',
          refresh_token: refreshToken
        }),
        headers: {
          'Content-Type': 'application/json'
        }
      });
      await this._handleAccessTokenResponse(response);
    }
    /**
     * @private
     */


    _buildBasicAuthHeaders() {
      if (this.clientSecret === null) {
        return {};
      }

      const credentials = `${this.clientId}:${this.clientSecret}`;
      return {
        Authorization: `Basic ${Buffer.from(credentials).toString('base64')}`
      };
    }
    /**
     * @private
     * @param {object} body
     * @param {object} headers
     */


    async _doAccessTokenRequest(body = {}, headers = {}) {
      const res = await fetch(`${this.mbUrl}/oauth/v1/token`, {
        method: 'POST',
        body: queryString.stringify(body),
        headers: _objectSpread2({}, headers, {
          'Content-Type': 'application/x-www-form-urlencoded'
        })
      });
      await this._handleAccessTokenResponse(res);
    }
    /**
     * @private
     * @param {Response} res - Express.js response object.
     */


    async _handleAccessTokenResponse(res) {
      const {
        error,
        error_description: errorDescription,
        errors,
        access_token: accessToken,
        token_type: tokenType,
        expires_in: expiresIn,
        refresh_token: refreshToken,
        expiration_time: expirationTime
      } = await res.json();

      if (error !== undefined && error !== null) {
        throw new AuthError(error, errorDescription);
      }

      if (errors) {
        console.error(errors);
        throw new AuthError(errors[0], errors[0]);
      }

      if (tokenType !== 'Bearer') {
        throw new Error('Unexpected token type.');
      }

      if (accessToken !== undefined && accessToken !== null) {
        this.setAccessToken(accessToken);
      } else {
        this.clearAccessToken();
      }

      if (expiresIn !== undefined && expiresIn !== null) {
        const expirationTimeValue = moment().add(expiresIn, 'seconds');
        this.setExpirationTime(expirationTimeValue.format());
      } else {
        this.clearExpirationTime();
      }

      if (expirationTime) {
        const expirationTimeValue = moment(expirationTime);
        this.setExpirationTime(expirationTimeValue.format());
      }

      if (refreshToken !== undefined && refreshToken !== null) {
        this.setRefreshToken(refreshToken);
      }
    }
    /**
     * Get basic information from the OAuth client with the given identifier.
     *
     * @param {string} clientIdentifier
     * @returns {object}
     */


    async getClientByIdentifier(clientIdentifier) {
      const json = await this._doGetRequest(`/v1/clients/client_identifier=${clientIdentifier}`);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'clients');
    }
    /**
     * Get basic information from the OAuth app with the given oauth identifier.
     *
     * @param {string} oAuthIdentifier
     * @returns {object}
     */


    async getAppProfileByOAuthIdentifier(oAuthIdentifier) {
      const json = await this._doGetRequest(`/v1/application_profiles/oauth_identifier=${oAuthIdentifier}`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Get basic information from the OAuth app with the given public client identifier.
     *
     * @param {string} oAuthIdentifier
     * @returns {object}
     */


    async getAppProfileByClientIdentifier(oAuthIdentifier) {
      const json = await this._doGetRequest(`/v1/application_profiles/client_identifier=${oAuthIdentifier}`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Retrives the user with the given handle.
     *
     * @param {string} handle
     * @returns {object}
     */


    async getUserByHandle(handle) {
      let json = await this._doGetRequest(`/v1/users/handle/${handle}`);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'users');
    }
    /**
     * Retrives the user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */


    async getUser(userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Get coinify auth tokens for current user.
     *
     * @param {string} userId
     * @returns {object}
     */


    async getCoinifyRefreshTokenById() {
      let coinifyAuthResponse = await this._doGetRequest(`/v1/coinify/auth-tokens`);
      return coinifyAuthResponse;
    }

    async getCoinifyPendingOperations() {
      let json = await this._doGetRequest(`/v1/coinify/pending-operations`);
      return json;
    }

    async registerCoinifyTrade(tradeId) {
      let json = await this._doPostRequest(`/v1/coinify/trade`, {
        tradeId
      });
      return json;
    }
    /**
     * Gets list of countries available for Coinify
     *
     * @returns {object}
     */


    async getCoinifyCountryList() {
      let countries = await this._doGetRequest(`/v1/coinify/countries`);
      return countries;
    }

    async registerInCoinify(location) {
      let refreshToken = await this._doPostRequest(`/v1/coinify/register`, {
        location
      });
      return refreshToken;
    }
    /**
     * Retrives the profile of user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */


    async getUserProfile(userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/profile`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Updates the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async updateUser(userId, attributes = {}) {
      const body = UserSerializer.serialize(attributes);
      const json = await this._doPatchRequest(`/v1/users/${userId}`, body);

      this._clearCurrentUser();

      return jsonApi.JsonDeserializer.deserialize(json);
    }

    async setOnboardCompleted() {
      const json = await this._doPatchRequest(`/v2/me/profile/onboard-completed`, {});

      this._clearCurrentUser();

      return json;
    }

    async setMnemonicBacked() {
      const json = await this._doPatchRequest(`/v2/me/profile/mnemonic-backed`, {});

      this._clearCurrentUser();

      return json;
    }
    /**
     * Retrives the transaction history of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */


    async getUserTransactionHistory(query = {}) {
      return this._doGetRequest(`/v2/me/payments/history`, query);
    }
    /**
     * Retrives the OAuth clients of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */


    async getUserClients(userId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/clients`, query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'clients');
    }
    /**
     * Retrives paginated utxos for the specified user
     *
     * @param {string} userId
     * @returns {list}
     */


    async getUserUtxos(userId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/utxos`, query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'utxos');
    }
    /**
     * Retrives an specific utxo for a user
     *
     * @param {string} userId
     * @param {string} utxoId
     * @returns {list}
     */


    async getUserUtxoById(userId, utxoId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/utxos/${utxoId}`, query);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'utxos');
    }
    /**
     * Retrives all the applications belonging to the specified user.
     *
     * @param {string} userId
     * @returns {list}
     */


    async getUserApplications(userId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/applications`, query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'applications');
    }

    async getUserApplicationById(userId, appId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/applications/${appId}`, query);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'applications');
    }

    async createUserApplication(userId, attributes) {
      const body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('applications', attributes));
      const json = await this._doPostRequest(`/v1/users/${userId}/applications`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'applications');
    }
    /**
     * Creates a new swipe permission.
     *
     * @param {string} attributes.amount Max amount to authorized.
     * @param {string} attributes.currency Currency of the authorized amount.
     */


    async createUserSpentAuthorization(attributes) {
      const body = SwipePermissionSerializer.serialize(attributes);
      const json = await this._doPostRequest(`/v1/swipe_permissions`, body);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Returns a list of swipe permissions associates with the current user.
     */


    async getCurrentUserSwipePermissions() {
      const json = await this._doGetRequest('/v1/swipe_permissions');
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Get the amount left for an specific permission.
     *
     * @param {string} token IMB permission token
     */


    async getSwipePermissionAmountLeft(token) {
      const json = await this._doPostRequest(`/v1/swipe_permissions/amount-left`, {
        authToken: token
      });
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Get the info for an specific swipe permission.
     *
     * @param {string} id ID of the permission
     */


    async getCurrentUserSwipePermissionById(id) {
      const json = await this._doGetRequest(`/v1/swipe_permissions/${id}`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }

    async updateCurrentUserSwipePermissionById(id, attributes) {
      const reqBody = SwipePermissionSerializer.serialize(attributes);
      const jsonResponse = await this._doPatchRequest(`/v1/swipe_permissions/${id}`, reqBody);
      return jsonApi.JsonDeserializer.deserialize(jsonResponse);
    }
    /**
     * Deletes an specific swipe permission.
     *
     * @param {string} id ID of the permission
     */


    async deleteCurrentUserSwipePermissionById(id) {
      await this._doDeleteRequest(`/v1/swipe_permissions/${id}`);
    }
    /**
     * Creates a new authorized payment.
     *
     * @param {string} attributes.amount Max amount to authorized.
     * @param {string} attributes.currency Currency of the authorized amount.
     */


    async createAuthorizedPayment(authorization, paymentAttributes, paymentOutputs, cryptoOperations) {
      const body = AuthorizedPaymentSerializer.serialize({
        authorization,
        paymentAttributes,
        paymentOutputs,
        cryptoOperations
      });
      const json = await this._doPostRequest(`/v1/swipe_permissions/make-payment`, body); // return JsonDeserializer.deserialize(json)

      return json;
    }

    async updateUserApplication(userId, appId, attributes) {
      const body = jsonApi.toJsonApiData(jsonApi.toResourceObject(appId, 'applications', attributes));
      const json = await this._doPatchRequest(`/v1/users/${userId}/applications/${appId}`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'applications');
    }
    /**
     * Creates an OAuth client for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async createUserClient(userId, attributes) {
      let body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('clients', attributes));
      const json = await this._doPostRequest(`/v1/users/${userId}/clients`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'clients');
    }
    /**
     * Updates an OAuth client for the user with the given user id.
     *
     * @param {string} userId
     * @param {string} clientId
     * @param {object} attributes
     * @returns {object}
     */


    async updateUserClient(userId, clientId, attributes = {}) {
      const body = jsonApi.toJsonApiData(jsonApi.toResourceObject(clientId, 'clients', attributes));
      await this._doPatchRequest(`/v1/users/${userId}/clients/${clientId}`, body);
    }
    /**
     * Retrives the handles of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */


    async getUserHandles(userId, query = {}) {
      const json = await this._doGetRequest(`/v1/users/${userId}/handles`, query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'handles');
    }
    /**
     * Update a handle with the proper data
     *
     * @param {string} handleId
     * @param {object} attributes
     * @returns {object}
     */


    async updateUserHandle(userId, handleId, attributes = {}) {
      const body = jsonApi.toJsonApiData(jsonApi.toResourceObject(handleId, 'handles', attributes));
      const json = await this._doPatchRequest(`/v1/users/${userId}/handles/${handleId}`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'handles');
    }
    /**
     * Retrives the handles of the user with the given user id.
     *
     * @param {string} userId
     * @param {object} query
     * @returns {object}
     */


    async checkHandleAvailability(search, query = {}) {
      let body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('handleChecks', {
        search
      }));
      const json = await this._doPostRequest(`/v1/handles/check`, body, query);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'handleAvailabilities');
    }
    /**
     * Creates a handle for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async createUserHandle(userId, attributes) {
      let body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('handles', attributes));
      const json = await this._doPostRequest(`/v1/users/${userId}/handles`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'handles');
    }
    /**
     * Retrives the wallet with the given wallet id for the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */


    async getUserWallet(userId, walletId) {
      let data = this.getStoredWalletData(userId, walletId);

      if (data == null) {
        const json = await this._doGetRequest(`/v1/users/${userId}/wallets/${walletId}`);
        data = jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'wallets');
        this.saveWalletData(userId, walletId, data);
      }

      return data;
    }
    /**
     * Retrives the wallets of the user with the given user id.
     *
     * @param {string} userId
     * @returns {object}
     */


    async getUserWallets(userId) {
      let json = await this._doGetRequest(`/v1/users/${userId}/wallets/`);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'wallets');
    }
    /**
     * Creates a wallet for the user with the given user id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async createUserWallet(userId, attributes) {
      let body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('wallets', attributes));
      let json = await this._doPostRequest(`/v1/users/${userId}/wallets`, body);

      this._clearCurrentUser();

      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'wallets');
    }
    /**
     * Retrieves the balance from the user with given user id.
     *
     * @param {string} userId
     * @returns {object}
     */


    async getBalance(userId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/balance`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Retrieves assets balances for active user
     *
     * @param {string} userId
     * @returns {object}
     */


    getWalletBalances(walletId = 'active') {
      return this._doGetRequest(`/v2/me/wallets/${walletId}/balances`);
    }
    /**
     * Retrives a recieve address for the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */


    async getReceiveAddress(userId, walletId) {
      let json = await this._doPostRequest(`/v1/users/${userId}/wallets/${walletId}/receive_address`);
      let {
        address
      } = jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'addresses');
      return address;
    }
    /**
     * Retrives a signed receive address for the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */


    async getReceiveAddressSignature(userId, walletId) {
      let json = await this._doPostRequest(`/v1/users/${userId}/wallets/${walletId}/receive_signed_address`);
      let {
        addressSignature,
        address
      } = jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'addresses');
      return {
        addressSignature,
        address
      };
    }
    /**
     * Converts a (curreny,amount) pair into the given user's default currency.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async getCurrencyAmount(userId, attributes) {
      const body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('currency', attributes));
      const json = await this._doPostRequest(`/v1/users/${userId}/currency`, body);
      const {
        amount,
        currency
      } = jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'currency');
      return {
        amount,
        currency
      };
    }
    /**
     * Retrives the balance for the wallet with the given wallet id,
     * belonging to the user with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @returns {object}
     */


    async getWalletBalance(userId, walletId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/wallets/${walletId}/balance`);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'amounts');
    }
    /**
     * Updates the wallet with the given wallet id, belonging to the user
     * with the given user id.
     *
     * @param {string} userId
     * @param {string} walletId
     * @param {object} attributes
     * @returns {object}
     */


    async updateWallet(userId, walletId, attributes) {
      const body = jsonApi.toJsonApiData(jsonApi.toResourceObject(walletId, 'wallets', attributes));
      await this._doPatchRequest(`/v1/users/${userId}/wallets/${walletId}`, body);
    }
    /**
     * Retrieves the payments from the user with the given user id.
     *
     * @param {string} userId
     * @param {object} paginate
     * @returns {object}
     */


    async getUserPayments(userId, paginate) {
      const json = await this._doGetRequest(`/v1/users/${userId}/payments?${this._paginateUri(paginate)}`);
      return {
        pages: json.meta['total-pages'],
        payments: json.data.map(payment => jsonApi.fromResourceObject(payment, 'payments'))
      };
    }
    /**
     * Query for a list of payments belonging to the user or app logged in in the client.
     *
     * @param {object} query Query parameters
     * @param {object} query.limit Pagination. Max amount of record returned.
     * @param {object} query.offset Pagination offset.
     */


    async getOwnPayments(query) {
      const json = await this._doGetRequest(`/v1/payments`, query);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * Query a payment by id.
     *
     * @param {number} paymentId
     */


    async getPaymentById(paymentId) {
      const json = await this._doGetRequest(`/v1/payments/${paymentId}`);
      return jsonApi.JsonDeserializer.deserialize(json);
    }
    /**
     * @private
     * @returns {string}
     */


    _paginateUri({
      number,
      size,
      sort
    }) {
      // NOTE: query-string does not support the nesting format used in JsonApi
      // https://github.com/sindresorhus/query-string#nesting
      // http://jsonapi.org/examples/#pagination
      // http://jsonapi.org/format/#fetching-pagination
      const url = [];
      if (number) url.push(`page[number]=${number}`);
      if (size) url.push(`page[size]=${size}`);
      if (sort) url.push(`sort=${sort}`);
      return url.join('&');
    }
    /**
     * Creates a payment for the user with the given user id to the specified payment
     * outputs.
     *
     * @param {string} userId
     * @param {object} attributes
     * @param {array} paymentOutputs
     * @returns {object}
     */


    async createUserPayment(userId, attributes, paymentOutputs, cryptoOperations = []) {
      return this._doPostRequest(`/v2/me/payments`, _objectSpread2({}, attributes, {
        paymentOutputs,
        cryptoOperations
      }));
    }
    /**
     * Estimates the amount to be spend in a payment to show it in the button.
     *
     * @param {string} userId
     * @param {object} attributes
     * @param {array} paymentOutputs
     * @returns {object}
     */


    async estimatePaymentAmount(userId, attributes, paymentOutputs, cryptoOperations = []) {
      return this._doPostRequest(`/v2/me/payments/estimate`, _objectSpread2({}, attributes, {
        paymentOutputs,
        cryptoOperations
      }));
    }
    /**
     * Retrives the payment with the given payment id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} paymentId
     * @returns {object}
     */


    async getUserPayment(paymentId) {
      return this._doGetRequest(`/v2/me/payments/${paymentId}`);
    }
    /**
     * Creates a deposit for the user with the given id.
     *
     * @param {string} userId
     * @param {object} attributes
     * @returns {object}
     */


    async createUserDeposit(userId, attributes) {
      const body = jsonApi.toJsonApiData(jsonApi.toNewResourceObject('deposits', attributes));
      const json = await this._doPostRequest(`/v1/users/${userId}/deposits`, body);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'deposits');
    }
    /**
     * Retrives the deposit with the given deposit id, belonging to the user with
     * the given user id.
     *
     * @param {string} userId
     * @param {string} depositId
     * @returns {object}
     */


    async getUserDeposit(userId, depositId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/deposits/${depositId}`);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'deposits');
    }
    /**
     *
     * @param {string} walletId
     * @returns {object}
     */


    async createUserRecoverFullAmountPayment(walletId) {
      return this._doPostRequest(`/v2/me/wallets/${walletId}/recover-full-amount`);
    }
    /**
     * Broadcasts the given payment. It must include a fully signed transaction.
     *
     * @param {Payment} payment
     * @returns {object}
     */


    async broadcastPayment(_ref) {
      let {
        id
      } = _ref,
          payment = _objectWithoutProperties(_ref, ["id"]);

      const body = payment;
      const json = await this._doPatchRequest(`/v2/payments/${id}/broadcast`, body);
      return json;
    }
    /**
     * Retrieves the list of supported cryptocurrencies.
     *
     * @param {object} query
     * @returns {array}
     */


    async getSupportedCryptocurrencies(query = {}) {
      const json = await this._doGetRequest('/v1/currencies/crypto', query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'currencies');
    }
    /**
     * Retrieves the list of supported fiat currencies.
     *
     * @param {object} query
     * @returns {array}
     */


    async getSupportedFiatCurrencies(query = {}) {
      const json = await this._doGetRequest('/v1/currencies/fiat', query);
      return jsonApi.fromResourceObjectsOfType(jsonApi.fromJsonApiData(json), 'currencies');
    }
    /**
     * Looks up ui data for given user.
     *
     * @param {String} userId
     */


    async fetchUiData(userId) {
      const json = await this._doGetRequest(`/v1/users/${userId}/ui-data`);
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'ui-data');
    }
    /**
     * Updates ui data for given user.
     *
     * @param {String} userId
     * @param {object} data
     */


    async updateUiData(userId, data) {
      const json = await this._doPatchRequest(`/v1/users/${userId}/ui-data`, jsonApi.toJsonApiData(jsonApi.toNewResourceObject('ui-data', data)));
      return jsonApi.fromResourceObject(jsonApi.fromJsonApiData(json), 'ui-data');
    }
    /**
     * Creates an asset definition for a user
     *
     * @param {string} protocol
     * @param {string} name
     * @param {number} initialSupply
     * @param {string} avatar
     * @param {string} paymailAlias
     * @param {string} paymailDomain
     * @param {string} url
     */


    createAsset(protocol, name, initialSupply, avatar, paymailAlias, paymailDomain, url) {
      return this._doPostRequest('/v2/me/assets', {
        protocol,
        name,
        initialSupply,
        avatar,
        paymailAlias,
        paymailDomain,
        url
      });
    }
    /**
     * Lists a user's assets
     *
     */


    getUserAssets() {
      return this._doGetRequest('/v2/me/assets');
    }
    /**
     * Adds a domain to the account
     *
     * @param {string} domain
     */


    createUserDomain(domain) {
      return this._doPostRequest('/v2/me/domains', {
        domain
      });
    }
    /**
     * Validates paymail DNS configuration for a domain
     *
     * @param {string} id
     */


    validateUserDomain(id) {
      return this._doPostRequest(`/v2/me/domains/${id}/validate`);
    }
    /**
     * Lists a user's domains
     *
     */


    getUserDomains() {
      return this._doGetRequest('/v2/me/domains');
    }
    /**
     * Remove a user domain
     *
     */


    deleteUserDomain(id) {
      return this._doDeleteRequest(`/v2/me/domains/${id}`);
    }
    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doGetRequest(endpoint, query = {}, accessToken = null) {
      let opts = {
        method: 'GET'
      };
      return this._doRequest(endpoint, opts, query, accessToken);
    }
    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doDeleteRequest(endpoint, query = {}, accessToken = null) {
      let opts = {
        method: 'DELETE'
      };
      return this._doRequest(endpoint, opts, query, accessToken);
    }
    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doPostRequest(endpoint, body = {}, query = {}, accessToken = null) {
      let opts = {
        method: 'POST',
        body: JSON.stringify(body)
      };
      return this._doRequest(endpoint, opts, query, accessToken);
    }
    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doPatchRequest(endpoint, body = {}, accessToken = null) {
      let opts = {
        method: 'PATCH',
        body: JSON.stringify(body)
      };
      return this._doRequest(endpoint, opts, {}, accessToken);
    }
    /**
     * @private
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} body - fetch request's body.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doPutRequest(endpoint, body = {}, accessToken = null) {
      let opts = {
        method: 'PUT',
        body: JSON.stringify(body)
      };
      return this._doRequest(endpoint, opts, {}, accessToken);
    }
    /**
     *
     * @param {string} endpoint - REST API relative endpoint.
     * @param {object} opts - fetch request options.
     * @param {object} query - URL query parameters.
     * @param {string} accessToken - auth API access token
     * @returns {object}
     */


    async _doRequest(endpoint, opts = {}, query = {}, accessToken = null) {
      const url = this._appendQuery(`${this.mbUrl}/api${endpoint}`, query);

      const contentType = endpoint.includes('v1') ? 'application/vnd.api+json' : 'application/json';
      const headers = {
        'Accept': contentType,
        'Content-Type': contentType
      };
      accessToken = accessToken || (await this.getValidAccessToken());

      if (accessToken !== null) {
        headers['Authorization'] = `Bearer ${accessToken}`;
      }

      const res = await fetch(url, _objectSpread2({}, opts, {
        headers
      }));
      let json = null;

      try {
        json = await res.json();
      } catch (e) {
        throw new RestError(res.status, 'api error', 'api error');
      }

      if (json.errors instanceof Array) {
        let error = json.errors[0];

        if (error.status) {
          let {
            status,
            title,
            detail
          } = error;
          throw new RestError(status, title, detail);
        }

        throw new Error(error.title);
      } else if (!res.ok) {
        if (res.status === 400) {
          console.info('API returned a validation failure', json);
          throw new RestError(res.status, 'API Validation Error', `There seems to be a problem with Money Button's configuration`);
        }

        throw new RestError(res.status, 'api error', 'api error');
      }

      return json;
    }
    /**
     * @private
     * @param {string} url - base URL where query will be appended.
     * @param {object} query - URL query parameters.
     * @returns {string}
     */


    _appendQuery(url, query = {}) {
      if (Object.keys(query).length === 0) {
        return url;
      }

      const {
        page
      } = query,
            queryWithoutPage = _objectWithoutProperties(query, ["page"]);

      if (page !== undefined) {
        for (const key in page) {
          queryWithoutPage[`page[${key}]`] = page[key];
        }
      }

      return `${url}?${queryString.stringify(queryWithoutPage, {
        arrayFormat: 'bracket'
      })}`;
    }
    /**
    *
    * Web location utilities.
    *
    */

    /**
     *
     */


    _getUrlQuery() {
      return queryString.parse(webLocation.search);
    }
    /**
     *
     * @param {string} uri - URI where the browser will be redirected to.
     */


    _redirectToUri(uri) {
      webLocation.href = uri;
    }
    /**
    *
    * Web storage utilities.
    *
    */

    /**
     * @private
     * @returns {string}
     */


    _getRedirectUri() {
      return webStorage.getItem(OAUTH_REDIRECT_URI_KEY);
    }
    /**
     * @private
     * @param {string} redirectUri - OAuth redirect URI from authorization grant flow.
     * @returns {undefined}
     */


    _setRedirectUri(redirectUri) {
      webStorage.setItem(OAUTH_REDIRECT_URI_KEY, redirectUri);
    }
    /**
     * @private
     * @returns {undefined}
     */


    _clearRedirectUri() {
      webStorage.removeItem(OAUTH_REDIRECT_URI_KEY);
    }
    /**
     * @private
     * @returns {undefined}
     */


    _getState() {
      return webStorage.getItem(OAUTH_STATE_KEY);
    }
    /**
     * @private
     * @param {string} state - OAuth state from authorization grant flow.
     * @returns {undefined}
     */


    _setState(state) {
      webStorage.setItem(OAUTH_STATE_KEY, state);
    }
    /**
     * @private
     * @returns {undefined}
     */


    _clearState() {
      webStorage.removeItem(OAUTH_STATE_KEY);
    }
    /**
     * Get information of a user wallet from the local storage cache.
     *
     * @param {string} userId
     * @param {string} walletId
     */


    getStoredWalletData(userId, walletId) {
      const rawData = webStorage.getItem(`${STORAGE_NAMESPACE}:${userId}:${walletId}:wallet_data`);

      try {
        return JSON.parse(rawData);
      } catch (e) {
        return null;
      }
    }
    /**
     * Stores wallet data into localStorage for cache.
     *
     * @param {string} userId
     * @param {string} walletId
     * @param {string} walletData
     */


    saveWalletData(userId, walletId, walletData) {
      const dataToSave = JSON.stringify(walletData);
      const key = `${STORAGE_NAMESPACE}:${userId}:${walletId}:wallet_data`;
      webStorage.setItem(key, dataToSave);
    }
    /**
     *
     * @param {*} key
     * @param {*} message
     * @returns
     */


    async _hashPassword(plainPassword) {
      return MoneyButtonClient._computeHmac256(LOGIN_PASSWORD_HMAC_KEY, plainPassword);
    }
    /**
     * Retrieve internal cache of current user
     *
     * @returns {object}
     */


    async _getCurrentUser() {
      if (this._currentUser === null) {
        const {
          id
        } = await this.getIdentity();
        const user = await this.getUser(id);
        this._currentUser = user;
      }

      return this._currentUser;
    }
    /**
     * Clears internal cache for current user.
     */


    _clearCurrentUser() {
      this._currentUser = null;
    }
    /**
     * Retrieves the currently-set access token.
     *
     * @returns {string}
     */


    getAccessToken() {
      return webStorage.getItem(OAUTH_ACCESS_TOKEN_KEY);
    }
    /**
     * Sets the given access token.
     *
     * @param {string} accessToken - auth API access token
     * @returns {undefined}
     */


    setAccessToken(accessToken) {
      webStorage.setItem(OAUTH_ACCESS_TOKEN_KEY, accessToken);
    }
    /**
     * Clears the currently-set access token.
     *
     * @returns {undefined}
     */


    clearAccessToken() {
      webStorage.removeItem(OAUTH_ACCESS_TOKEN_KEY);
    }
    /**
     * Returns the currently-set token's expiration time in the following
     * format: 'YYYY-MM-DDTHH:mm:ssZ'.
     * For example, '2018-10-25T13:08:58-03:00'.
     *
     * @returns {string}
     */


    getExpirationTime() {
      return webStorage.getItem(OAUTH_EXPIRATION_TIME_KEY);
    }
    /**
     * Sets the currently-set token's expiration time. The argument must be
     * in the following format: 'YYYY-MM-DDTHH:mm:ssZ'.
     * For example, '2018-10-25T13:08:58-03:00'.
     *
     * @param {string} expirationTime
     * @returns {undefined}
     */


    setExpirationTime(expirationTime) {
      webStorage.setItem(OAUTH_EXPIRATION_TIME_KEY, expirationTime);
    }
    /**
     * Clears the currently-set access token's expiration time.
     *
     * @returns {undefined}
     */


    clearExpirationTime() {
      webStorage.removeItem(OAUTH_EXPIRATION_TIME_KEY);
    }
    /**
     * Retrieves the currently-set refresh token.
     *
     * @returns {string}
     */


    getRefreshToken() {
      return webStorage.getItem(OAUTH_REFRESH_TOKEN_KEY);
    }

    getRefreshTokenStorageKey() {
      return OAUTH_REFRESH_TOKEN_KEY;
    }
    /**
     * Sets the given refresh token.
     *
     * @param {string} refreshToken - auth API refresh token
     * @returns {undefined}
     */


    setRefreshToken(refreshToken) {
      webStorage.setItem(OAUTH_REFRESH_TOKEN_KEY, refreshToken);
    }
    /**
     * Clears the currently-set refresh token.
     * @returns {undefined}
     */


    clearRefreshToken() {
      webStorage.removeItem(OAUTH_REFRESH_TOKEN_KEY);
    }
    /**
    *
    * Web crypto utilities.
    *
    */

    /**
     * @private
     * @param {string} key - HMAC key.
     * @param {string} message- HMAC message.
     * @returns {string}
     */


    static async _computeHmac256(key, message) {
      const hash = sha256.hmac(Buffer.from(key), Buffer.from(message));
      return Buffer.from(hash).toString('hex');
    }

  }

  return MoneyButtonClient;
}

const MoneyButtonClient = getMoneyButtonClient(localStorage, new Window().location);

exports.AuthError = AuthError;
exports.MoneyButtonClient = MoneyButtonClient;
exports.RestError = RestError;
//# sourceMappingURL=moneybutton.client.cjs.js.map
