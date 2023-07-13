class AuthClient {

    /**
     * @param {string} serverUrl
     */
    constructor(serverUrl) {
        this.serverUrl = serverUrl;
        this.authenticated = false;
    }

    /**
     *
     * @param uri {string?}
     * @param username {string}
     * @param password {string}
     * @returns {Promise<void>}
     */
    async register(uri = '/register', username, password) {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
            })
        });
        if (response.status === 200) {
            const data = await response.json();

            this.username = username;
            this.authenticated = true;

            this.refresh_token = data.refresh_token;
            this.access_token = data.access_token;

            return;
        }

        throw new Error('Registration failed ' + response.status);

    }

    /**
     *
     * @param uri {string?}
     * @param username {string}
     * @param password {string}
     * @returns {Promise<void>}
     */
    async login(uri= '/login', username, password) {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username,
                password,
            })
        });
        if (response.status === 200) {
            const data = await response.json();

            this.username = username;
            this.authenticated = true;

            this.refresh_token = data.refresh_token;
            this.access_token = data.access_token;

        }

        throw new Error('Login failed ' + response.status);
    }

    async logout(uri = '/logout') {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: this.username,
                refresh_token: this.refresh_token,
            })
        });
        if (response.status === 200) {
            this.authenticated = false;
            this.username = null;
            this.refresh_token = null;
            this.access_token = null;

            return;
        }

        throw new Error('Logout failed ' + response.status);

    }

    async refresh(uri = '/refresh') {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: this.username,
                refresh_token: this.refresh_token,
            })
        });
        if (response.status === 200) {
            const data = await response.json();

            this.refresh_token = data.refresh_token;
            this.access_token = data.access_token;
            return;
        }

        throw new Error('Refresh failed ' + response.status);
    }


    // admin only - user management

    /**
     *
     * @param uri {string?}
     * @param username {string}
     * @param roles {string[]}
     * @returns {Promise<void>}
     */
    async setRoles(uri = '/set-roles', username, roles) {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
                roles,
            })
        });
        if (response.status === 200) {
            return;
        }
        throw new Error('Set roles failed ' + response.status);
    }

    /**
     *
     * @param uri {string?}
     * @param username {string}
     * @returns {Promise<void>}
     */
    async blacklist(uri = '/blacklist', username) {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
            })
        });
        if (response.status === 200) {
            return;
        }
        throw new Error('Blacklist failed ' + response.status);
    }

    /**
     *
     * @param uri {string?}
     * @param username {string}
     * @returns {Promise<void>}
     */
    async unblacklist(uri = '/unblacklist', username) {
        const response = await fetch(this.serverUrl + uri, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
            })
        });
        if (response.status === 200) {
            return;
        }
        throw new Error('Unblacklist failed ' + response.status);
    }

}