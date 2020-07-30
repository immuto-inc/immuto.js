/* COPYRIGHT 2020 under the MIT License
 * Immuto, Inc
 */
let IN_BROWSER = ("undefined" !== typeof window)

var Web3 = require('web3')
var sigUtil = require('eth-sig-util')
var NodeHTTP = require('xmlhttprequest').XMLHttpRequest // for backend compatability
var NodeForm = require('form-data')                     // for backend compatability
var crypto = require('crypto')
const NodeRSA = require('node-rsa');

const SYMMETRIC_SCHEME="aes-256-ctr"
const VALID_RECORD_TYPES=["basic", "editable"]
const DEV_ENDPOINT  = "https://dev.immuto.io"
const PROD_ENDPIONT = "https://api.immuto.io"

function new_HTTP() {
    if (IN_BROWSER) return new XMLHttpRequest()
    else return new NodeHTTP()
}

function new_Form() { // for sending files with XMLHttpRequest
    if (IN_BROWSER) return new FormData()
    else return new NodeForm()
}

exports.init = function(debug, debugHost) {    
    this.host = PROD_ENDPIONT
    if (debug === true) {
        if (debugHost)
            this.host = debugHost
        else 
            this.host = DEV_ENDPOINT // reasonable default
    }

    this.web3 = new Web3(PROD_ENDPIONT) // Dummy provider because required on init now
    
    // for web3 account management
    this.salt = ""
    this.encryptedKey = ""

    // for API acess
    this.authToken = ""
    this.email = ""

    if (IN_BROWSER) {
        let ls = window.localStorage // preserve session across pages
        if (ls.IMMUTO_authToken && ls.IMMUTO_email && ls.IMMUTO_salt && ls.IMMUTO_encryptedKey) {
            this.salt = ls.IMMUTO_salt
            this.encryptedKey = ls.IMMUTO_encryptedKey
            this.authToken = ls.IMMUTO_authToken
            this.email = ls.IMMUTO_email.toLowerCase()
        }
    }

    this.utils = {
        convert_unix_time: function(time_ms) {
            let time_seconds = time_ms * 1000
            var a = new Date(time_seconds);
            var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            var year = a.getFullYear();
            var month = months[a.getMonth()];
            var date = a.getDate();
            var hour = a.getHours();
            var min = a.getMinutes() < 10 ? '0' + a.getMinutes() : a.getMinutes(); 
            var sec = a.getSeconds() < 10 ? '0' + a.getSeconds() : a.getSeconds();
            var time = date + ' ' + month + ' ' + year + ' ' + hour + ':' + min + ':' + sec ;
            return time;
        },
        convert_js_time: function(time_js) {
            return this.convert_unix_time(time_js / 1000)
        },
        emails_to_addresses: (emails) => {
            return new Promise((resolve, reject) => {
                var http = new_HTTP()

                let sendstring = "emails=" + emails + "&authToken=" + this.authToken

                http.open("POST", this.host + "/emails-to-addresses", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = function() {
                    if (http.readyState === 4 && http.status === 200) {
                        try {
                            let addresses = JSON.parse(http.responseText) 
                            resolve(addresses)
                        } catch (err) {
                            console.error(http.responseText)
                            reject(err)
                        }
                    } else if (http.readyState === 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
        },
        addresses_to_emails: (history) => {
            return new Promise((resolve, reject) => {
                let addresses = []
                for (let event of history) {
                    addresses.push(event.signer)
                }

                var http = new_HTTP()

                let sendstring = "addresses=" + JSON.stringify(addresses) + "&authToken=" + this.authToken

                http.open("POST", this.host + "/addresses-to-emails", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = function() {
                    if (http.readyState === 4 && http.status === 200) {
                        try {
                            let addrToEmail = JSON.parse(http.responseText) 
                            for (let i = 0; i < history.length; i++) {
                                history[i].email = addrToEmail[history[i].signer]
                            }
                            resolve(history)
                        } catch (err) {
                            reject(err)
                        }
                    } else if (http.readyState === 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
        },
        ecRecover: (message, v, r, s) => {
            if (v === '28') {
                    v = Buffer.from('1c', 'hex')
            } else {
                    v = Buffer.from('1b', 'hex')
            }
           
            r = Buffer.from(r.split('x')[1], 'hex')
            s = Buffer.from(s.split('x')[1], 'hex')

            let signature = sigUtil.concatSig(v, r, s)
            let address = sigUtil.recoverPersonalSignature({data: message, sig: signature})
            return this.web3.utils.toChecksumAddress(address)
        },
        parse_record_ID: (recordID) => {
            if (!recordID) throw new Error("recordID is required");
            if ("string" !== typeof recordID) throw new Error("recordID must be string");

            if (recordID.length !== 48) {
                throw new Error(`Invalid recordID: ${recordID}, reason: length not 48`)
            }

            return {
                address: recordID.substring(0, 42),
                shardHex: recordID.substring(42)
            }
        },
        shard_to_URL: (shardIndex) => {
            if (!shardIndex && shardIndex !== 0) {
                throw new Error("No prefix given")
            }

            if (shardIndex === 0) { return "http://localhost:8443" } 

            if (this.host === PROD_ENDPIONT) { 
                return `https://prod${shardIndex}.immuto.io:8443` 
            }

            return `https://shard${shardIndex}.immuto.io:8443`
        },

        shardIndex_to_hex: (shardIndex) => {
            const SHARD_LENGTH = 6
            if (shardIndex > 16777215) { // ffffff
                throw new Error(`shardIndex: ${shardIndex} exceeds width of ${SHARD_LENGTH}`)
            }
            if (shardIndex < 0) {
                throw new Error(`shardIndex must be a positive integer`)
            }

            let hexString = Number(shardIndex).toString(16)

            while (hexString.length < SHARD_LENGTH) {
                hexString = "0" + hexString
            }

            return hexString
        },

        hex_to_shardIndex: (hexString) => {
            if (!hexString) throw new Error("hexString is required")
            if (typeof hexString !== "string") throw new Error(`hexString must be a string, got ${typeof hexString}`)

            return parseInt(hexString, 16)
        }
    }

    this.decrypt_account = function(password) {
        if (!password) throw new Error("password is required")

        try {
            return this.web3.eth.accounts.decrypt( 
                this.encryptedKey, 
                password + this.salt 
            );
        } catch(err) {
            throw new Error("Incorrect password")
        }
    }

    this.get_registration_token = function(address) {
        return new Promise((resolve, reject) => {
            if (!address) {
                reject("User's address is required"); return;
            }

            var http = new_HTTP()

            let sendstring = "address=" + address

            http.open("POST", this.host + "/get-signature-data", true)
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")

            http.onreadystatechange = () => {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(http.responseText)
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            }
            http.send(sendstring)
        })
    }

    this.register_user = function(email, password, orgToken) {
        return new Promise((resolve, reject) => {
            if (!email) {
                reject("User email is required"); return;
            }
            if (!password) {
                reject("User password is required"); return;
            }

            email = email.toLowerCase()
            let salt = this.web3.utils.randomHex(32)
            let account = this.web3.eth.accounts.create()
            let address = account.address
            let encryptedKey = this.web3.eth.accounts.encrypt(account.privateKey, password + salt);


            this.get_registration_token(address)
            .then((token) => {
                let signature = account.sign(token)
                var http = new_HTTP()

                let sendstring = "email=" + email 
                sendstring += "&password=" + this.web3.utils.sha3(password)
                sendstring += "&salt=" + salt
                sendstring += "&address=" + address
                sendstring += "&keyInfo=" + JSON.stringify(encryptedKey)
                sendstring += "&signature=" + JSON.stringify(signature)

                if (orgToken)
                    sendstring += "&registrationCode=" + orgToken

                http.open("POST", this.host + "/submit-registration", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")

                http.onreadystatechange = () => {
                    if (http.readyState === 4 && http.status === 204) {
                        resolve()
                    } else if (http.readyState === 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
            .catch(err => reject(err))
        })
    }


    // Best for backend use only, while authenticated as organization admin
    this.permission_new_user = function(newUserEmail) {
        return new Promise((resolve, reject) => {
            if (!newUserEmail) {
                reject("User email is required");
                return;
            }

            let sendstring = "email=" + newUserEmail.toLowerCase()
            sendstring += "&noEmail=true" // Causes API to respond with authToken rather than emailing user
            sendstring += "&authToken=" + this.authToken // org admin authToken for permissioning new user registration
            
            const http = new_HTTP()
            http.open("POST", this.host + "/submit-org-member", true)
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = () => {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(http.responseText)
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            }
            http.send(sendstring)
        })
    }

    this.submit_login = function(email, password) {
        return new Promise((resolve, reject) => {
            let http = new_HTTP()
            let sendstring = "email=" + email 
            sendstring += "&password=" + this.web3.utils.sha3(password) // server does not see password

            http.open("POST", this.host + "/submit-login", true)
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = () => {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(JSON.parse(http.responseText))
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            }
            http.send(sendstring)
        })
    }

    this.prove_address = function(authToken, email, password) {
        return new Promise((resolve, reject) => {
            let account = {}
            try {
                account = this.decrypt_account(password)
            } catch(err) {
                reject(err); return;
            }

            let signature = account.sign(authToken)
            let sendstring = "address=" + account.address
            sendstring += "&signature=" + JSON.stringify(signature)
            sendstring += "&authToken=" + authToken
            sendstring += "&returnUserInfo=" + true

            let http2 = new_HTTP()
            http2.open("POST", this.host + "/prove-address", true)
            http2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http2.onreadystatechange = () => {
                if (http2.readyState === 4 && (http2.status === 204 || http2.status === 200)) {
                    if (http2.status === 204) {
                        resolve(authToken)
                        return
                    }

                    let userInfo = JSON.parse(http2.responseText)
                    if (userInfo.publicKey) { // already generated RSA keypair
                        resolve(authToken)
                        return
                    }

                    this.generate_RSA_keypair(password)
                    .catch(err => console.error(err))
                    .finally(() => resolve(authToken))
                } else if (http2.readyState === 4) {
                    console.error("Error on login verification")
                    reject(http2.responseText)
                }
            }
            http2.send(sendstring)
        })
    }

    this.authenticate = async function(email, password) {
        if (!email) { throw new Error("Email required for authentication") }
        if (!password) { throw new Error("Password required for authentication") }

        if (this.authToken) {
            await this.deauthenticate()
        } 

        email = email.toLowerCase()
        const loginResponse = await this.submit_login(email, password)
        if (loginResponse.result === "Your email or password are incorrect.") { 
            throw new Error("Incorrect password") 
        }

        this.salt = loginResponse.salt
        this.encryptedKey = loginResponse.encryptedKey
        this.authToken = loginResponse.authToken
        this.email = email
        if (IN_BROWSER) {
            window.localStorage.IMMUTO_salt = this.salt
            window.localStorage.IMMUTO_encryptedKey = this.encryptedKey
            window.localStorage.IMMUTO_authToken = this.authToken
            window.localStorage.IMMUTO_email = this.email
        }

        return await this.prove_address(this.authToken, email, password)
    }

    this.reset_state = function() {
        if (IN_BROWSER) {
            window.localStorage.IMMUTO_authToken = ""
            window.localStorage.IMMUTO_email = ""
            window.localStorage.IMMUTO_salt = ""
            window.localStorage.IMMUTO_encryptedKey = ""
        }
        this.authToken = ""
        this.email = ""
        this.salt = ""
        this.encryptedKey = ""
    }

    this.deauthenticate = function() {
        return new Promise((resolve, reject) => {
            const authToken = this.authToken || (IN_BROWSER ? window.localStorage.IMMUTO_authToken : "") 
            let sendstring = `authToken=${authToken}`
            
            this.reset_state()
            
            var http = new_HTTP();
            http.open("POST", this.host + "/logout-API", true);
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = () => {
                if (http.readyState === 4 && http.status === 204) {
                    resolve() 
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };
            http.send(sendstring);
        })
    }

    this.update_encryption_info = function(encryptedKey, hashedPassword) {
        return new Promise((resolve, reject) => {
            const xhr = new_HTTP();

            xhr.open("POST", this.host + "/reset-password", true);
            xhr.setRequestHeader("Content-Type", "application/json")
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 204) {
                    resolve() 
                } else if (xhr.readyState === 4) {
                    reject(xhr.responseText)
                }
            };

            encryptedKey = JSON.stringify(encryptedKey)
            const query = {
                encryptedKey,
                hashedPassword,
                authToken: this.authToken
            }

            xhr.send(JSON.stringify(query));
        })
    }

    this.reset_password = async function(oldPassword, newPassword) {
        if (!oldPassword) throw new Error("oldPassword required")
        if (!newPassword) throw new Error("newPassword required")
        if (oldPassword === newPassword) throw new Error("oldPassword and newPassword must not match")
        if (!this.authToken) throw new Error("User must be authenticated to reset password")

        const uInfo = await this.get_user_info()
        const account = this.decrypt_account(oldPassword)

        const encryptedKey = account.encrypt(newPassword + uInfo.userSalt) // leave salt unchanged 
        const hashedPassword = this.web3.utils.sha3(newPassword)

        await this.update_encryption_info(encryptedKey, hashedPassword)

        // reauthenticate with updated info
        await this.authenticate(this.email, newPassword)
    }

    // convenience method for signing an arbitrary string
    // user address can be recovered from signature by utils.ecRecover
    this.sign_string = function(string, password) {
        if (!string) throw new Error("string is required for signing")
        if (!password) throw new Error("password is required to sign string")

        let account =  this.decrypt_account(password) // throws error on bad password
        return account.sign(string)
    }

    this.get_public_key = function(email) {
        return new Promise((resolve, reject) => {
            if (!email) {
                reject("email is required")
                return
            }

            let accessURL = this.host + "/public-key-for-user?email=" + email
            accessURL += "&authToken=" + this.authToken

            var http = new_HTTP();
            http.open("GET", accessURL, true);
            http.setRequestHeader('Accept', 'application/json, text/javascript');
            http.onreadystatechange = function() {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(http.responseText)
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };

            http.send()
        })

    }

    this.decrypt_RSA_private_key = function(encryptedKey, rsaIv, password) {
        if (!encryptedKey) {
            throw new Error("encryptedKey is required for decryption")
        }
        if (!rsaIv) {
            throw new Error("iv is required for decryption")
        }
        if (!password) {
            throw new Error("Password is required to decrypt RSA key")
        }

        const decryptKey = this.generate_key_from_password(password)  
        const iv = this.string_to_iv(rsaIv)
        return this.decrypt_string(encryptedKey, decryptKey, iv, 'base64')
    }

    this.generate_RSA_keypair = function(password) {
        return new Promise((resolve, reject) => {
            if (!password) {
                reject("Password is required to generate RSA keypair")
                return;
            }

            const rsaKey = NodeRSA({b: 2048})
            const pubKey = rsaKey.exportKey('public')
            const privKey = rsaKey.exportKey('private')
            const encrypted = this.encrypt_string_with_password(privKey, password, 'base64')
            
            const iv = this.iv_to_string(encrypted.iv)
            const encryptedPrivateKey = encrypted.ciphertext

            var form = new_Form()
            form.append('publicKey', pubKey)
            form.append('privateKey', encryptedPrivateKey)
            form.append('rsaIv', iv)
            form.append('authToken', this.authToken)

            const url =  this.host + "/set-rsa-keypair"
            if (IN_BROWSER) {
                var xhr = new_HTTP()
                xhr.open("POST", url, true);
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 204) {
                        resolve({pubKey, privKey})
                    } else if (xhr.readyState === 4) {
                        console.error("Error on upload")
                        reject(xhr.responseText)
                    }
                };
                xhr.send(form)
            } else {
                form.submit(url, function(err/*, res*/) {
                    if (err) {
                        reject(err)
                        return
                    }
                    resolve({pubKey, privKey})
                })
            }
        })
    }

    this.generate_key_from_password = function(password) {
        if (!password) {
            throw new Error("Password is required to generate key")
        }
        const account = this.decrypt_account(password)

        const hash = crypto.createHash("sha512")
        hash.update(account.privateKey);
        return hash.digest().slice(0, 32) // key for aes-256 must be 32 bytes
    }

    this.iv_to_string = function(iv) {
        if (!iv) {
            throw new Error("No iv given")
        }

        let str = ""
        for (let i = 0; i < iv.length; i ++) {
            str += iv[i] + ","
        }
        return str
    }

    this.string_to_iv = function(str) {
        if (!str) {
            throw new Error("No string given")
        }

        let ivStr = str.split(',')

        let iv = new Uint8Array(16)
        for (let i = 0; i < ivStr.length; i++) {
            iv[i] = ivStr[i]
        }

        return iv
    }

    this.encrypt_with_publicKey = function(plaintext, publicKey) {
        if (!plaintext) { throw new Error("No plaintext given") }
        if (!publicKey) { throw new Error("No publicKey given") }

        const key = new NodeRSA(publicKey)
        return key.encrypt(plaintext, 'base64')
    }

    this.decrypt_with_privateKey = function(ciphertext, privateKey) {
        if (!ciphertext) { throw new Error("No ciphertext given") }
        if (!privateKey) { throw new Error("No privateKey given") }

        const key = new NodeRSA(privateKey)
        return key.decrypt(ciphertext, 'utf8')
    }

    this.encrypt_string_with_key = function(plaintext, key, encoding) {
        if (!plaintext) { throw new Error("No plaintext given") }
        if (!key) { throw new Error("No key given") }

        encoding = encoding || 'binary'

        const iv = crypto.randomBytes(16)
        const cipher = crypto.createCipheriv(SYMMETRIC_SCHEME, key, iv)
        let ciphertext = cipher.update(plaintext, 'binary', encoding);
        ciphertext += cipher.final(encoding);

        return {
            ciphertext: ciphertext,
            key: key,
            iv: iv
        }
    }

    this.encrypt_string_with_password = function(plaintext, password, encoding) {
        if (!plaintext) {throw new Error("No plaintext given") }
        if (!password) { throw new Error("No password given") }

        let key = this.generate_key_from_password(password)
        return this.encrypt_string_with_key(plaintext, key, encoding)
    }

    this.encrypt_string = function(plaintext, encoding) {
        if (!plaintext) { throw new Error("No plaintext given") }

        const key = crypto.randomBytes(32)
        return this.encrypt_string_with_key(plaintext, key, encoding)
    }

    this.decrypt_string = function(ciphertext, key, iv, encoding) {
        if (!ciphertext) { throw new Error("No ciphertext given") }
        if (!key) { throw new Error("No key given") }
        if (!iv) { throw new Error("No iv given") }

        encoding = encoding || 'binary'
        let decipher = crypto.createDecipheriv(SYMMETRIC_SCHEME, key, iv)
        let decrypted = decipher.update(ciphertext, encoding, 'binary');
        return decrypted + decipher.final('binary');
    }

    this.str2ab = function(str) {
        if (!str) { throw new Error("No str given") }

        var buf = new ArrayBuffer(str.length); // 2 bytes for each char
        var bufView = new Uint8Array(buf);
        for (var i=0, strLen=str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return bufView;
    }

    this.ab2str = function(buffer) {
        if (!buffer) { throw new Error("No buffer given") }
    
        let str = ""

        for (let charCode of buffer) {
            str += String.fromCharCode(charCode)
        }

        return str
    }

    this.get_file_content = function(file) {
        return new Promise((resolve, reject) => {
            if (!file) { reject("No file given"); return; }

            var reader = new FileReader();
            reader.onload = function() {
                resolve(this.result)
            }
            reader.onerror = function(e) {
                reject(e)
            }
            reader.readAsBinaryString(file);
        })
    }

    // iv for aes256, optional for RSA
    this.store_user_key_for_record = function(userEmail, recordID, encryptedKey, iv) {
        return new Promise((resolve, reject) => {
            if (!userEmail) { reject("No userEmail given"); return; }
            if (!recordID) { reject("No recordID given"); return; }
            if (!encryptedKey) { reject("No encryptedKey given"); return; }
            this.utils.parse_record_ID(recordID) // throws error on bad record

            const url =  this.host + "/set-key-for-record"
            let form = new_Form()
            form.append('userForKey', userEmail)
            form.append('recordID', recordID)
            form.append('encryptedKey', encodeURI(encryptedKey))
            if (iv) form.append('iv', this.iv_to_string(iv))
            form.append('authToken', this.authToken)

            if (IN_BROWSER) {
                let xhr = new_HTTP()
                xhr.open("POST", url, true);
                xhr.onreadystatechange = function() {
                    if (xhr.readyState === 4 && xhr.status === 204) {
                        resolve()
                    } else if (xhr.readyState === 4) {
                        reject(xhr.responseText)
                    }
                };
                xhr.send(form);
            } else {
                form.submit(url, function(err/*, res*/) {
                    if (err) {
                        reject(err)
                        return
                    }
                    resolve()
                })
            }
        })
    }

    this.upload_file_for_record = function(file, fileContent, recordID, password, projectID, handleProgress) {
        return new Promise((resolve, reject) => {
            if (!file) { reject("No file given"); return; }
            if (!fileContent) { reject("No fileContent given"); return; }
            if (!recordID) { reject("No recordID given"); return; }
            if (!password) { reject("No password given"); return; }


            let cipherInfo = this.encrypt_string(fileContent)
            
            let encryptedKey = this.encrypt_string_with_password(
            JSON.stringify({
                key: cipherInfo.key,
                iv: this.iv_to_string(cipherInfo.iv)
            }), password, 'base64')

            let encryptedFile = new Blob([this.str2ab(cipherInfo.ciphertext)], {type: file.type});
            encryptedFile.lastModifiedDate = new Date();
            encryptedFile.name = file.name;

            let sendstring  = 'fileSize=' + encryptedFile.size
            sendstring += '&fileName=' + file.name
            sendstring += '&fileType=' + file.type
            sendstring += '&recordID=' + recordID
            if (projectID) sendstring += '&projectID=' + projectID
            sendstring += '&authToken=' + this.authToken

            var xhr = new_HTTP()
            let url =  this.host + "/prepare-file-upload"
            xhr.open("POST", url, true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    let presignedPostData = JSON.parse(xhr.responseText)
                    
                    const formData = new FormData();
                    Object.keys(presignedPostData.fields).forEach(key => {
                      formData.append(key, presignedPostData.fields[key]);
                    });

                    // Actual file has to be appended last
                    formData.append("file", encryptedFile);

                    const http = new_HTTP();

                    http.open("POST", presignedPostData.url, true);
                    
                    http.onreadystatechange = () => {
                        if (http.readyState === 4 && http.status === 204) {
                            this.store_user_key_for_record(this.email, recordID, encryptedKey.ciphertext, encryptedKey.iv)
                            .then(() => resolve("done"))
                            .catch(err => reject(err))
                        } else if (http.readyState === 4){
                            reject(http.responseText)
                        }
                    };

                    http.upload.onprogress = function(e) {
                        let percentComplete = Math.ceil((e.loaded / e.total) * 100);
                        if (handleProgress) {
                            handleProgress(percentComplete)
                        }
                    };

                    http.send(formData);
                } else if (xhr.readyState === 4) {
                    console.error("Error on upload")
                    reject(xhr.responseText)
                }
            };
            xhr.send(sendstring);
        })
    }

    this.upload_file = function(file, password, projectID, handleProgress) {
        return new Promise((resolve, reject) => {
            if (!file) { reject("No file given"); return; }
            if (!password) { reject("No password given"); return; }

            this.get_file_content(file)
            .then((content) => {
                this.create_data_management(content, file.recordName || file.name, "editable", password, "")
                .then((recordID) => {
                    this.upload_file_for_record(file, content, recordID, password, projectID, handleProgress)
                    .then(() => resolve(recordID))
                    .catch(err => reject(err))
                })
                .catch(err => reject(err))
            })
            .catch(err => reject(err))
        })
    }

    this.upload_file_data = function(fileContent, fileName, password, projectID, handleProgress) {
        return new Promise((resolve, reject) => {
            if (!fileContent) { reject("No fileContent given"); return; }
            if (!fileName) { reject("No fileName given"); return; }
            if (!password) { reject("No password given"); return; }

            let file = {name: fileName, type: "text/plain"}
            projectID = projectID || ''

            this.create_data_management(fileContent, fileName, "editable", password, "")
            .then((recordID) => {
                this.upload_file_for_record(file, fileContent, recordID, password, projectID, handleProgress)
                .then(() => resolve(recordID))
                .catch(err => reject(err))
            })
            .catch(err => reject(err))
        })
    }

    this.download_file_data = function(recordID, password, version) {
        version = version || 0
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            if (!password) { reject("No password given"); return; }
            try {
                this.utils.parse_record_ID(recordID)
            } catch(err) {
                reject(err); return;
            }

            this.download_file_for_recordID(recordID, password, version, true)
            .then(file => resolve(file.data))
            .catch(err => reject(err))
        })
    }

    this.search_records_by_hash = function(hash) {
        return new Promise((resolve, reject) => {
            if (!hash) { reject("No hash given"); return; }

            let accessURL = this.host + "/records-for-hash?hash=" + hash
            accessURL += "&authToken=" + this.authToken

            var http = new_HTTP();
            http.open("GET", accessURL, true);
            http.setRequestHeader('Accept', 'application/json, text/javascript');
            http.onreadystatechange = function() {
                if (http.readyState === 4 && http.status === 200) {
                    let records = JSON.parse(http.responseText)
                    for (let i = 0; i < records.length; i++) {
                        records[i].recordID = records[i].contractAddr // so contractAddr remains internal language
                    }

                    resolve({records, hash})
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };

            http.send()
        })
    }

    this.search_records_by_content = function(fileContent) {
        if (typeof fileContent !== "string") {
            try {
                fileContent = this.ab2str(fileContent)
            } catch(err) {
                throw new Error(`Failed to convert data to string: ${err}`)
            }
        }

        return this.search_records_by_hash(this.web3.eth.accounts.hashMessage(fileContent))
    }

    this.search_records_by_query = function(query) {
        return new Promise((resolve, reject) => {
            if (!query) { reject("No query given"); return; }

            let accessURL = this.host + '/search-user-data-contracts'
            accessURL += "?authToken=" + this.authToken

            var http = new_HTTP();
            http.open("POST", accessURL, true);
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = function() {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(JSON.parse(http.responseText))
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };

            http.send(`searchQuery=${query}`)
        })
    }

    this.get_info_for_recordID = function(recordID) {
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            try {
                this.utils.parse_record_ID(recordID)
            } catch(err) {
                reject(err); return;
            }

            let accessURL = this.host + "/record-for-user?recordID=" + recordID 
            accessURL += "&authToken=" + this.authToken

            var http = new_HTTP();
            http.open("GET", accessURL, true);
            http.setRequestHeader('Accept', 'application/json, text/javascript');
            http.onreadystatechange = function() {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(JSON.parse(http.responseText))
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };

            http.send()
        })
    }

    this.build_full_URL = function(remoteURL) {
        if (!remoteURL) { throw new Error("No remoteURL given") }

        const S3_BUCKET = this.host === PROD_ENDPIONT ? "immuto-prod" : "immuto-sandbox"

        if (remoteURL.includes(S3_BUCKET)) return remoteURL

        return "https://" + S3_BUCKET +  ".s3.amazonaws.com/readable/" + remoteURL
    }

    this.decrypt_fileKey_symmetric = function(encryptedKeyInfo, password) {
        if (!encryptedKeyInfo) { throw new Error("No encryptedKeyInfo given") }
        if (!password) { throw new Error("No password given") }

        let decryptKey = this.generate_key_from_password(password)  
        let encryptedKey = encryptedKeyInfo.encryptedKey
        let iv = this.string_to_iv(encryptedKeyInfo.iv)

        let fileDecryptInfo = this.decrypt_string(encryptedKey, decryptKey, iv, 'base64')

        let parsed = JSON.parse(fileDecryptInfo)          
        let fileDKey = parsed.key.data
        let fileDiv = this.string_to_iv(parsed.iv)

        return {
            key: fileDKey,
            iv: fileDiv
        }
    }

    this.decrypt_fileKey_asymmetric = async function(encryptedKeyInfo, password) {   
        if (!encryptedKeyInfo) { throw new Error("No encryptedKeyInfo given") }
        if (!password) { throw new Error("No password given") }

        const encryptedKey = encryptedKeyInfo.encryptedKey
        const userInfo = await this.get_user_info()
        const privateKey = this.decrypt_RSA_private_key(userInfo.privateKey, userInfo.rsaIv, password)
        let fileDecryptInfo = JSON.parse(this.decrypt_with_privateKey(encryptedKey, privateKey))
        fileDecryptInfo.iv = this.string_to_iv(fileDecryptInfo.iv)
        return fileDecryptInfo
    }

    this.key_to_string = function(keyInfo) {
        if (!keyInfo) { throw new Error("No keyInfo given") }
        if (!keyInfo.iv) { throw new Error("Given keyInfo has no iv field") }
        
        keyInfo.iv = this.iv_to_string(keyInfo.iv)
        return JSON.stringify(keyInfo)
    }

    this.get_encrypted_file = function(fileURL) {
        return new Promise((resolve, reject) => {
            if (!fileURL) { reject("No fileURL given"); return; }

            let http = new_HTTP();
            http.open("GET", this.build_full_URL(fileURL), true);
            http.responseType = "arraybuffer"
            http.onreadystatechange = () => {
                if (http.readyState === 4 && http.status === 200) {
                    resolve(new Uint8Array(http.response))
                    
                } else if (http.readyState === 4) {
                    reject(http.responseText)
                }
            };
            http.send()
        })
    }

    this.download_file_for_record = async function(recordInfo, password, version, asPlaintext) {
        if (!recordInfo) { throw new Error("No recordInfo given"); }
        if (!recordInfo.files) { throw new Error("No files exist for record") }
        if (!password) { throw new Error("No password given"); }
        if (version < 0) { throw new Error("Version number must be non-negative integer") }
        if (version >= recordInfo.files.length) {
            throw new Error(`Invalid version number ${version} for record with ${recordInfo.files.length} versions`)
        }
        if (version !== 0)
            version = version || recordInfo.files.length - 1 // default to recent
        const fileInfo = recordInfo.files[version]
        let fileURL = fileInfo.remoteURL

        let encryptedKeyInfo = recordInfo[this.email.toLowerCase().replace(/\./g, " ")]

        if (!encryptedKeyInfo) {
            throw new Error(`User ${this.email} does not have key for decrypting file`);
        }

        let fileDecryptInfo = {}
        if (encryptedKeyInfo.iv) { // for symmetric, personal key, non-RSA
            fileDecryptInfo = this.decrypt_fileKey_symmetric(encryptedKeyInfo, password) 
        } else { // for RSA
            fileDecryptInfo = await this.decrypt_fileKey_asymmetric(encryptedKeyInfo, password) 
        }
        let fileDKey = fileDecryptInfo.key
        let fileDiv = fileDecryptInfo.iv

        let encryptedData = await this.get_encrypted_file(fileURL)
        let plaintext = this.decrypt_string(encryptedData, fileDKey, fileDiv, 'base64') // this can be used for auto-verification (before splitting)

        let file = {
            type: fileInfo.type,
            name: fileInfo.name,
            data: asPlaintext ? plaintext : this.str2ab(plaintext)
        }
        return file
    }

    this.download_file_for_recordID = async function(recordID, password, version, asPlaintext) {
        if (!recordID) { throw new Error("recordID is required"); }
        if (!password) { throw new Error("password is required"); }
        this.utils.parse_record_ID(recordID) // throws error on bad record

        let recordInfo = await this.get_info_for_recordID(recordID)
        let file = await this.download_file_for_record(recordInfo, password, version, asPlaintext)
        return file
    }

    this.get_user_info = function() {
        return new Promise((resolve, reject) => {
            var xhr = new_HTTP();

            let url = this.host + '/get-user-info?authToken=' + this.authToken
            xhr.open("GET", url, true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    resolve(JSON.parse(xhr.responseText)) 
                } else if (xhr.readyState === 4) {
                    reject(xhr.responseText)
                }
            };
            xhr.send();
        })
    }

    this.share_record_access = function(recordID, shareEmail) {
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            if (!shareEmail) { reject("No shareEmail given"); return; }

            try {
                this.utils.parse_record_ID(recordID)
            } catch(err) {
                reject(err); return;
            }

            var xhr = new_HTTP();

            xhr.open("POST", this.host + '/share-record', true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 204) {
                    resolve(xhr.responseText) 
                } else if (xhr.readyState === 4) {
                    reject(xhr.responseText)
                }
            };

            let sendstring = 'recordID=' + recordID
            sendstring += '&shareEmail=' + shareEmail
            sendstring += '&authToken=' + this.authToken
            xhr.send(sendstring);
        })
    }

    this.share_record = async function(recordID, shareEmail, password) {
        if (!recordID) throw new Error("RecordID is required")
        if (!shareEmail) throw new Error("shareEmail is required")
        if (!password) throw new Error("passowrd is required")
        
        await this.share_record_access(recordID, shareEmail)
        let recordInfo = await this.get_info_for_recordID(recordID)
        let publicKey = await this.get_public_key(shareEmail)

        if (recordInfo.creator.toLowerCase() !== this.email.toLowerCase()) {
            throw new Error(`Only the record creator ${recordInfo.creator} may share file content`)
        }
        if (!recordInfo.files || (recordInfo.files && recordInfo.files.length === 0)) {
            throw new Error("No files exist for record");
        }
        let keyField = this.email.toLowerCase().replace(/\./g, " ")
        if (!recordInfo[keyField]) {
            throw new Error(`No key set for user ${this.email}`);
        }

        const keyInfo = this.decrypt_fileKey_symmetric(recordInfo[keyField], password)
        const keyString = this.key_to_string(keyInfo)
        const encryptedKey = this.encrypt_with_publicKey(keyString, publicKey)

        await this.store_user_key_for_record(shareEmail, recordID, encryptedKey)
    }

    this.create_data_management = function(content, name, type, password, desc) {
        return new Promise((resolve, reject) => {
            if (!content) { reject("No content given"); return; }
            if (!name) { reject("No name given"); return; }
            if (!type) { reject("No type given"); return; }
            if (!password) { reject("No password given"); return; }

            type = type.toLowerCase()
            if (!VALID_RECORD_TYPES.includes(type)) { reject(`Invalid type: ${type}`); return; }

            if (typeof content !== "string") {
                try {
                    content = this.ab2str(content)
                } catch(err) {
                    throw new Error(`Failed to convert data to string: ${err}`)
                }
            }

            // Good practice to keep account encrypted unless in use (signing transaction)
            let account = {}
            try {
                account = this.decrypt_account(password)
            } catch(err) {
                reject(err); return;
            }

            let signature = account.sign(content)
            signature.message = "" // Maintain data privacy

            var xhr = new_HTTP();

            xhr.open("POST", this.host + "/submit-new-data-upload", true);
            xhr.setRequestHeader("Content-Type", "application/json")
            xhr.onreadystatechange = () => {
                if (xhr.readyState === 4 && xhr.status === 200) {
                    resolve(xhr.responseText) 
                } else if (xhr.readyState === 4) {
                    reject(xhr.responseText)
                }
            };

            const query = {
                filename: name,
                filedesc: desc,
                signature: JSON.stringify(signature),
                type,
                authToken: this.authToken
            }

            xhr.send(JSON.stringify(query));
        })
    }

    this.update_data_management = function(recordID, newContent, password) {
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            if (!newContent) { reject("No newContent given"); return; }
            if (!password) { reject("No password given"); return; }

            if (!this.utils.parse_record_ID(recordID)) {
                reject("Invalid recordID"); return; 
            }

            if (typeof newContent !== "string") {
                try {
                    newContent = this.ab2str(newContent)
                } catch(err) {
                    throw new Error(`Failed to convert data to string: ${err}`)
                }
            }

            let account = {}
            try {
                account = this.decrypt_account(password)
            } catch(err) {
                reject(err); return;
            }
            this.get_data_management_history(recordID, 'editable').then((history) => {
                let priorHash = history.pop().hash
                let signature = account.sign(newContent + priorHash)
                signature.message = "" // Waste of space to send full message

                var xhr = new_HTTP();
                let sendstring = ""

                xhr.open("POST", this.host + "/update-data-storage", true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                xhr.onreadystatechange = () => {
                    if (xhr.readyState === 4 && xhr.status === 204) {
                        resolve()
                    } else if (xhr.readyState === 4) {
                        reject(xhr.responseText)
                    }
                };

                sendstring += 'contractAddr=' + recordID // from submit-new-data-upload
                sendstring += '&signature=' + JSON.stringify(signature)
                sendstring += '&authToken=' + this.authToken
                sendstring += '&plainHash=' + this.web3.eth.accounts.hashMessage(newContent) 
                xhr.send(sendstring);
            }).catch((err) => {
                reject(err)
            })
        })
    }

    this.get_data_management_history = function(recordID, type) {
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            if (!type) { reject("No type given"); return; }

            type = type.toLowerCase()
            if (!VALID_RECORD_TYPES.includes(type)) { reject(`Invalid type: ${type}`); return; }

            let recordInfo = this.utils.parse_record_ID(recordID)

            if (!recordInfo) {
                reject("Invalid recordID"); return; 
            }

            let shardIndex = this.utils.hex_to_shardIndex(recordInfo.shardHex)
            const web3 = new Web3(this.utils.shard_to_URL(shardIndex))

            let contract = undefined
            if (type === "basic") {
                contract = new web3.eth.Contract(BASIC_DATA_STORAGE_ABI, recordInfo.address);
            } else if (type === "editable") {
                contract = new web3.eth.Contract(EDITABLE_DATA_STORAGE_ABI, recordInfo.address);
            } else {
                console.warn(`Unexpected type: ${type}... defaulting to editable`)
                contract = new web3.eth.Contract(EDITABLE_DATA_STORAGE_ABI, recordInfo.address);
            }
            
            contract.getPastEvents('Updated', {
                fromBlock: 0
            })
            .then((events) => {
                let history = []
                for (let i = 0; i < events.length; i++) {
                    let event = events[i]
                    history.push({
                        timestamp: this.utils.convert_unix_time(event.returnValues.timestamp),
                        hash: event.returnValues.hash,
                        signer: event.returnValues.updater
                    })
                }
                resolve(history)
            }).catch((err) => {
                reject(err)
            })
        })
    }

    this.verify_data_management = function (recordID, type, verificationContent) {
        return new Promise((resolve, reject) => {
            if (!recordID) { reject("No recordID given"); return; }
            if (!type) { reject("No type given"); return; }
            if (!verificationContent) { reject("No verificationContent given"); return; }

            type = type.toLowerCase()
            if (!VALID_RECORD_TYPES.includes(type)) { reject(`Invalid type: ${type}`); return; }

            if (typeof verificationContent !== "string") {
                try {
                    verificationContent = this.ab2str(verificationContent)
                } catch(err) {
                    throw new Error(`Failed to convert data to string: ${err}`)
                }
            }

            let recordInfo = this.utils.parse_record_ID(recordID)
            if (!recordInfo) {
                reject("Invalid recordID"); return; 
            }

            this.get_data_management_history(recordID, type).then((history) => {
                this.utils.addresses_to_emails(history).then((history) => {
                    for (let i = 0; i < history.length; i++) {
                        let priorHash = ""
                        if (i > 0) 
                            priorHash = history[i - 1].hash

                        let hash = this.web3.eth.accounts.hashMessage(verificationContent + priorHash)
                        if (hash.toLowerCase() === history[i].hash.toLowerCase()) {
                            resolve(history[i])
                            return
                        }
                    }
                    resolve(false)
                }).catch((err) => {
                    reject(err)
                })
            }).catch((err) => {
                reject(err)
            })
        })
    }

    return this
}


const BASIC_DATA_STORAGE_ABI = [
        {
                "inputs": [
                        {
                                "name": "hash",
                                "type": "bytes32"
                        },
                        {
                                "name": "v",
                                "type": "uint8"
                        },
                        {
                                "name": "r",
                                "type": "bytes32"
                        },
                        {
                                "name": "s",
                                "type": "bytes32"
                        }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "constructor"
        },
        {
                "anonymous": false,
                "inputs": [
                        {
                                "indexed": false,
                                "name": "timestamp",
                                "type": "uint256"
                        },
                        {
                                "indexed": false,
                                "name": "hash",
                                "type": "bytes32"
                        },
                        {
                                "indexed": false,
                                "name": "updater",
                                "type": "address"
                        }
                ],
                "name": "Updated",
                "type": "event"
        }
]

const EDITABLE_DATA_STORAGE_ABI = [
        {
                "constant": false,
                "inputs": [
                        {
                                "name": "hash",
                                "type": "bytes32"
                        },
                        {
                                "name": "v",
                                "type": "uint8"
                        },
                        {
                                "name": "r",
                                "type": "bytes32"
                        },
                        {
                                "name": "s",
                                "type": "bytes32"
                        }
                ],
                "name": "update",
                "outputs": [],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
        },
        {
                "inputs": [
                        {
                                "name": "hash",
                                "type": "bytes32"
                        },
                        {
                                "name": "v",
                                "type": "uint8"
                        },
                        {
                                "name": "r",
                                "type": "bytes32"
                        },
                        {
                                "name": "s",
                                "type": "bytes32"
                        }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "constructor"
        },
        {
                "anonymous": false,
                "inputs": [
                        {
                                "indexed": false,
                                "name": "timestamp",
                                "type": "uint256"
                        },
                        {
                                "indexed": false,
                                "name": "hash",
                                "type": "bytes32"
                        },
                        {
                                "indexed": false,
                                "name": "updater",
                                "type": "address"
                        }
                ],
                "name": "Updated",
                "type": "event"
        }
]
