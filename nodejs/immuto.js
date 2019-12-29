/* COPYRIGHT 2019 under the MIT License
 * Immuto, Inc
 */

var Web3 = require('web3')
var sigUtil = require('eth-sig-util')
var XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest

exports.init = (debug, debugHost) => {    
    this.host = "https://www.immuto.io"
    if (debug === true) {
        if (debugHost)
            this.host = debugHost
        else 
            this.host = "https://dev.immuto.io" // reasonable default
    }

    try {
        this.web3 = new Web3("https://www.immuto.io") // Dummy provider because required on init now
    } catch(err) {
        console.error(err)
        throw "Web3js is a required dependency of the Immuto API. Make sure it is included wherever immuto.js is present."
    }
    
    // for web3 account management
    this.salt = ""
    this.encryptedKey = ""

    // for API acess
    this.authToken = ""

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
        emails_to_addresses: (emails) => {
            return new Promise((resolve, reject) => {
                var http = new XMLHttpRequest()

                let sendstring = "emails=" + emails + "&authToken=" + this.authToken

                http.open("POST", this.host + "/emails-to-addresses", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = function() {
                    if (http.readyState == 4 && http.status == 200) {
                        try {
                            let addresses = JSON.parse(http.responseText) 
                            resolve(addresses)
                        } catch (err) {
                            reject(err)
                        }
                    } else if (http.readyState == 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
        },
        addresses_to_emails: (history) => {
            return new Promise((resolve, reject) => {
                addresses = []
                for (let event of history) {
                    addresses.push(event.signer)
                }

                var http = new XMLHttpRequest()

                let sendstring = "addresses=" + JSON.stringify(addresses) + "&authToken=" + this.authToken

                http.open("POST", this.host + "/addresses-to-emails", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = function() {
                    if (http.readyState == 4 && http.status == 200) {
                        try {
                            let addrToEmail = JSON.parse(http.responseText) 
                            for (let i = 0; i < history.length; i++) {
                                history[i].email = addrToEmail[history[i].signer]
                            }
                            resolve(history)
                        } catch (err) {
                            reject(err)
                        }
                    } else if (http.readyState == 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
        },
        ecRecover: (message, v, r, s) => {
            if (v == '28') {
                    v = Buffer.from('1c', 'hex')
            } else {
                    v = Buffer.from('1b', 'hex')
            }
           
            r = Buffer.from(r.split('x')[1], 'hex')
            s = Buffer.from(s.split('x')[1], 'hex')

            let signature = sigUtil.concatSig(v, r, s)
            let address = sigUtil.recoverPersonalSignature({data: message, sig: signature})
            return this.web3.utils.toChecksumAddress(address)
        }
    }

    this.establish_connection = function(email) {
        return new Promise((resolve, reject) => {
            if (!email) {
                reject("Email required for connection")
                return
            }

            var http = new XMLHttpRequest()

            let sendstring = "email=" + email.toLowerCase()
            http.open("GET", this.host + "/shard-public-node", true)
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = () => {
                if (http.readyState == 4 && http.status == 200) {
                    let URI = http.responseText
                    try {
                        this.web3 = new Web3(URI)
                        resolve()
                    } catch (err) {
                        reject(err)
                    }
                } else if (http.readyState == 4) {
                    reject(http.responseText)
                }
            }
            http.send(sendstring)
        })
    }

    this.establish_manual_connection = function(URI) {
        this.web3 = new Web3(URI)
    }

    
    this.get_registration_token = function(address) {
        return new Promise((resolve, reject) => {
            var http = new XMLHttpRequest()

            let sendstring = "address=" + address

            http.open("POST", this.host + "/get-signature-data", true)
            http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")

            http.onreadystatechange = () => {
                    if (http.readyState == 4 && http.status == 200) {
                        resolve(http.responseText)
                    } else if (http.readyState == 4) {
                        reject(http.responseText)
                    }
            }
            http.send(sendstring)
        })
    }

    this.register_user = function(email, password, orgToken) {
        return new Promise((resolve, reject) => {
            let salt = this.web3.utils.randomHex(32)
            let account = this.web3.eth.accounts.create()
            let address = account.address
            let encryptedKey = this.web3.eth.accounts.encrypt(account.privateKey, password + salt);

            this.get_registration_token(address).then((token) => {
                let signature = account.sign(token)
                var http = new XMLHttpRequest()

                let sendstring = "email=" + email 
                sendstring += "&password=" + this.web3.utils.sha3(password)
                sendstring += "&salt=" + salt
                sendstring += "&address=" + address
                sendstring += "&keyInfo=" + JSON.stringify(encryptedKey)
                sendstring += "&signature=" + JSON.stringify(signature)

                if (orgToken)
                    sendstring += "&registrationCode=" + orgToken

                http.open("POST", this.host + "/submit-registration", true)
                http.setRequestHeader("Content-type", "application/x-www-form-urlencoded")

                http.onreadystatechange = () => {
                    if (http.readyState == 4 && http.status == 204) {
                        resolve()
                    } else if (http.readyState == 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring)
            })
        })
    }

    this.authenticate = function(email, password) {
        return new Promise((resolve, reject) => {
            if (!email) {
                reject("Email required for authentication")
                return
            }
            if (!password) {
                reject("Password required for authentication")
                return
            }

            this.establish_connection(email).then(() => {
                let http = new XMLHttpRequest()

                let sendstring = "email=" + email 
                sendstring += "&password=" + this.web3.utils.sha3(password)

                http.open("POST", this.host + "/submit-login", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = () => {
                    if (http.readyState === 4 && http.status == 200) {
                        let response = JSON.parse(http.responseText)
                        this.salt = response.salt
                        this.encryptedKey = response.encryptedKey
                        this.authToken = response.authToken
                        
                        let account = undefined
                        try {
                            account = this.web3.eth.accounts.decrypt( 
                                this.encryptedKey, 
                                password + this.salt 
                            );
                        } catch(err) {
                            reject("Incorrect password")
                            return
                        }
                        
                        let signature = account.sign(this.authToken)

                        let sendstring = "address=" + account.address
                        sendstring += "&signature=" + JSON.stringify(signature)
                        sendstring += "&authToken=" + this.authToken

                        let http2 = new XMLHttpRequest()
                        http2.open("POST", this.host + "/prove-address", true)
                        http2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                        http2.onreadystatechange = () => {
                            if (http2.readyState == 4 && http2.status == 204) {
                                resolve(this.authToken)
                            } else if (http2.readyState == 4) {
                                console.error("Error on login verification")
                                reject(http2.responseText)
                            }
                        }
                        http2.send(sendstring)
                    } else if (http.readyState === 4){
                        console.error("Error on login")
                        reject(http.status + ": " + http.responseText)
                    }
                }
                http.send(sendstring)
            }).catch((err) => {
                console.error(err)
                reject("Could not establish connection to verification server")
            })
        })
    }

    this.deauthenticate = function() {
        return new Promise((resolve, reject) => {
            this.authToken = ""
            this.email = ""
            this.salt = ""
            this.encryptedKey = ""
            this.connected = false

            var http = new XMLHttpRequest();
            http.open("GET", this.host + "/logout-API", true);
            http.setRequestHeader('Accept', 'application/json, text/javascript');
            http.onreadystatechange = () => {
                if (http.readyState == 4 && http.status == 204) {
                    resolve() 
                } else if (http.readyState == 4) {
                    reject(http.responseText)
                }
            };

            http.send();
        })
    }

    this.set_authentication = function(authToken, salt, keystore) {
        throw "Unimplemented"

        if (!authToken) {
            throw "Invalid authToken: " + authToken
        }

        if (!salt) {
            throw "Invalid salt: " + salt
        }

        if (!keystore) {
             throw "Invalid keystore: " + keystore
        }
    }

    // convenience method for signing an arbitrary string
    // user address can be recovered from signature by utils.ecRecover
    this.sign_string = function(string, password) {
        let account = undefined;
        try { 
            account = this.web3.eth.accounts.decrypt(
                this.encryptedKey, 
                password + this.salt
            );

            return account.sign(string)
        } catch(err) {
            if (!this.email) {
                throw("User not yet authenticated.");
            } else {
                throw(err)
            }
            return;
        }
    }

    this.create_data_management = function(content, name, type, password, desc) {
        return new Promise((resolve, reject) => {

            // Good practice to keep account encrypted unless in use (signing transaction)
            let account = undefined;
            try { 
                account = this.web3.eth.accounts.decrypt(
                    this.encryptedKey, 
                    password + this.salt
                );
            } catch(err) {
                reject(err);
                return;
            }

            let signature = account.sign(content)
            signature.message = "" // Maintain data privacy

            var xhr = new XMLHttpRequest();
            //var fd = new FormData();
            let sendstring = ""

            xhr.open("POST", this.host + "/submit-new-data-upload", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState == 4 && xhr.status == 200) {
                    resolve(xhr.responseText) 
                } else if (xhr.readyState == 4) {
                    reject(xhr.responseText)
                }
            };

            sendstring += 'filename=' + name
            sendstring += '&filedesc=' + desc
            sendstring += '&signature=' + JSON.stringify(signature)
            sendstring += '&type=' + type
            sendstring += '&authToken=' + this.authToken
            xhr.send(sendstring);
        })
    }

    this.update_data_management = function(recordID, newContent, password) {
        return new Promise((resolve, reject) => {
            let account = undefined;
            try {
                account = this.web3.eth.accounts.decrypt(
                    this.encryptedKey, 
                    password + this.salt
                );
            } catch(err) {
                reject(err);
                return;
            }

            this.get_data_management_history(recordID, 'editable').then((history) => {
                let priorHash = history.pop().hash
                let signature = account.sign(newContent + priorHash)
                signature.message = "" // Waste of space to send full message

                var xhr = new XMLHttpRequest();
                //var fd = new FormData();
                let sendstring = ""

                xhr.open("POST", this.host + "/update-data-storage", true);
                xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                xhr.onreadystatechange = () => {
                    if (xhr.readyState == 4 && xhr.status == 204) {
                        resolve()
                    } else if (xhr.readyState == 4) {
                        reject(xhr.responseText)
                    }
                };

                sendstring += 'contractAddr=' + recordID // from submit-new-data-upload
                sendstring += '&signature=' + JSON.stringify(signature)
                sendstring += '&authToken=' + this.authToken
                xhr.send(sendstring);
            }).catch((err) => {
                reject(err)
            })
        })
    }

    this.get_data_management_history = function(recordID, type) {
        return new Promise((resolve, reject) => {
            if (this.web3) { // be more thorough later
                let contract = undefined
                if (type === "basic") {
                    contract = new this.web3.eth.Contract(BASIC_DATA_STORAGE_ABI, recordID);
                } else if (type === "editable") {
                    contract = new this.web3.eth.Contract(EDITABLE_DATA_STORAGE_ABI, recordID);
                } else {
                    reject("Invalid contract type: " + type)
                    return
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
            } else {
               reject("Connection to verification server not established. Call establish_connection to setup a connection.")
            }
        })
    }

    this.verify_data_management = function (recordID, type, verificationContent) {
        return new Promise((resolve, reject) => {
            if (this.web3) { // be more thorough later
                this.get_data_management_history(recordID, type).then((history) => {
                    this.utils.addresses_to_emails(history).then((history) => {
                        for (let i = 0; i < history.length; i++) {
                            let priorHash = ""
                            if (i > 0) 
                                priorHash = history[i - 1].hash

                            let hash = this.web3.eth.accounts.hashMessage(verificationContent + priorHash)
                            if (hash.toLowerCase() == history[i].hash.toLowerCase()) {
                                resolve(history[i])
                                return
                            }
                        }
                        resolve(false)
                    }).catch((err) => {
                        console.error(err)
                    })
                }).catch((err) => {
                    reject(err)
                })
            } else {
               reject("Connection to verification server not established. Call establish_connection to setup a connection.")
            }
        })
    }

    this.create_digital_agreement = function(content, name, type, password, signers, desc) {
        return new Promise((resolve, reject) => {
            let account = undefined;
            try {
                account = this.web3.eth.accounts.decrypt(
                    this.encryptedKey, 
                    password + this.salt
                );
            } catch(err) {
                return err;
            }

            let hashedData = this.web3.utils.sha3(content)
            let signature = account.sign(hashedData)
            signature.message = "" // Unnecessary for request

            var xhr = new XMLHttpRequest();
            //var fd = new FormData();
            let sendstring = ""

            xhr.open("POST", this.host + "/submit-new-agreement-upload", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState == 4 && xhr.status == 200) {
                    resolve(xhr.responseText)
                } else if (xhr.readyState == 4) {
                    reject(xhr.responseText)
                }
            };
            sendstring += 'filename=' + name
            sendstring += '&filedesc=' + desc
            sendstring += '&signature=' + JSON.stringify(signature)
            sendstring += '&type=' + type
            if (type == 'multisig')
                    sendstring += '&signers=' + JSON.stringify(signers)
            sendstring += '&fileHash=' + hashedData
            sendstring += '&authToken=' + this.authToken

            xhr.send(sendstring);
        })

    }

    this.sign_digital_agreement = function(recordID, password) {
        return new Promise((resolve, reject) => {
            let account = undefined;
            try {
                account = this.web3.eth.accounts.decrypt(
                    this.encryptedKey, 
                    password + this.salt
                );
            } catch(err) {
                return err;
            }

            var http = new XMLHttpRequest()

            let sendstring = "contractAddr=" + recordID 
            sendstring += "&authToken=" + this.authToken 

            http.open("POST", this.host + "/get-contract-info", true)
            http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            http.onreadystatechange = () => {
                if (http.readyState == 4 && http.status == 200) {
                    let response = JSON.parse(http.responseText)

                    let currentHash =  response.hashes.pop()
                    let signature = account.sign(currentHash)
                    signature.message = "" // Unnecessary for request

                    var xhr = new XMLHttpRequest();
                    //var fd = new FormData();
                    sendstring = ""

                    xhr.open("POST", this.host + "/sign-agreement", true);
                    xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                    xhr.onreadystatechange = () => {
                        if (xhr.readyState == 4 && xhr.status == 204) {
                            resolve()
                        } else if (xhr.readyState == 4) {
                            reject(xhr.responseText)
                        }
                    };
                    sendstring += 'contractAddr=' + recordID
                    sendstring += '&signature=' + JSON.stringify(signature)
                    sendstring += '&authToken=' + this.authToken

                    xhr.send(sendstring);
                } else if (http.readyState == 4) {
                    reject(http.responseText)
                }
            }
            http.send(sendstring) 

            
        })

    }

    this.update_digital_agreement = function(recordID, newContent, password) {
        return new Promise((resolve, reject) => {
            let account = undefined;
            try {
                account = this.web3.eth.accounts.decrypt(
                    this.encryptedKey, 
                    password + this.salt
                );
            } catch(err) {
                return err;
            }
            password = undefined

            let dataHash = this.web3.utils.sha3(newContent)
            let signature = account.sign(dataHash)
            signature.message = "" // Unnecessary for request

            var xhr = new XMLHttpRequest();
            //var fd = new FormData();
            let sendstring = ""

            xhr.open("POST", this.host + "/update-agreement", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
            xhr.onreadystatechange = () => {
                if (xhr.readyState == 4 && xhr.status == 204) {
                    resolve()
                } else if (xhr.readyState == 4) {
                    reject(xhr.responseText)
                }
            };
            sendstring += 'contractAddr=' + recordID
            sendstring += '&signature=' + JSON.stringify(signature)
            sendstring += '&docHash=' + dataHash
            sendstring += '&authToken=' + this.authToken

            xhr.send(sendstring);
        })

    }

    this.verify_digital_agreement = function(recordID, type, verificationContent) {
        return new Promise((resolve, reject) => {
            if (this.web3) { // be more thorough later
                var http = new XMLHttpRequest()

                let sendstring = "contractAddr=" + recordID 
                sendstring += "&authToken=" + this.authToken 

                http.open("POST", this.host + "/get-contract-info", true)
                http.setRequestHeader("Content-Type", "application/x-www-form-urlencoded")
                http.onreadystatechange = () => {
                    if (http.readyState == 4 && http.status == 200) {
                        let response = JSON.parse(http.responseText)
                        let hashes =  response.hashes
                        let hash = this.web3.utils.sha3(verificationContent)
                        let emails = response.signers
                        if (emails) {
                            this.get_digital_agreement_history(recordID, type).then((history) => {
                                this.utils.emails_to_addresses(JSON.stringify(emails)).then((addresses) => {
                                    validSignatures = []
                                    addresses.push(response.userAddr)
                                    for (let i = 0; i < addresses.length; i++) {
                                        addresses[i] = addresses[i].toLowerCase()
                                    }
                                    let addressLookup = new Set(addresses)
                                    let currentVersion = 0

                                    for (let i = 0; i < history.length; i++) {
                                        let sig = history[i].signature

                                        //causes extra if original hash correct, rest not
                                        for (let j = currentVersion; j < hashes.length; j++) {
                                            if (j > i) break;
                                            if (hashes[j].toLowerCase() == hash.toLowerCase()) {
                                                let address = this.utils.ecRecover(hash, sig.v, sig.r, sig.s)
                                                if (addressLookup.has(address.toLowerCase())) {
                                                    validSignatures.push({
                                                        version: j,
                                                        timestamp: history[i].timestamp,
                                                        hash: hash,
                                                        signer: address,
                                                        email: history[i]
                                                    })
                                                    break;
                                                } else {
                                                    currentVersion ++
                                                }
                                            }
                                        }
                                    }
                                    if (validSignatures.length > 0) {
                                        this.utils.addresses_to_emails(validSignatures).then((validSignatures) => {
                                            resolve(validSignatures)
                                        }).catch((err) => {
                                            reject(err)
                                        })
                                    }
                                    else {
                                        resolve(false)
                                    }
                                }).catch((err) => {
                                    reject(err)
                                })
                            }).catch((err) => {
                                reject(err)
                            })
                        } else {
                            this.get_digital_agreement_history(recordID, type).then((history) => {
                                let sig = history[0].signature

                                let address = this.utils.ecRecover(hash, sig.v, sig.r, sig.s)
                                this.utils.addresses_to_emails([{signer: address}]).then((emails) => {
                                    if (address.toLowerCase() == response.userAddr.toLowerCase()) {
                                        resolve([{
                                            version: 0,
                                            timestamp: history[0].timestamp,
                                            hash: hash,
                                            signer: address,
                                            email: emails[0].email
                                        }])
                                    } else {
                                        resolve(false)
                                    }
                                }).catch((err) => {
                                    reject(err)
                                })
                            }).catch((err) => {
                                reject(err)
                            })
                        }

                        
                    } else if (http.readyState == 4) {
                        reject(http.responseText)
                    }
                }
                http.send(sendstring) 
            } else {
               reject("Connection to verification server not established. Call establish_connection to setup a connection.")
            }
        })
    }

    this.get_digital_agreement_history = function(recordID, type) {
        return new Promise((resolve, reject) => {
            if (this.web3) { // be more thorough later
                let contract = undefined
                if (type === "single_sign") {
                    contract = new this.web3.eth.Contract(SINGLE_SIGN_AGREEMENT_ABI, recordID);
                } else if (type === "multisig") {
                    contract = new this.web3.eth.Contract(MULTISIG_AGREEMENT_ABI, recordID);
                } else {
                    reject("Invalid contract type: " + type)
                    return
                }
                
                contract.getPastEvents('Signed', {
                    fromBlock: 0,
                    toBlock: 'latest'
                })
                .then((events) => {
                    let history = []
                    for (let i = 0; i < events.length; i++) {
                        let event = events[i]

                        let v = event.returnValues.v
                        let r = event.returnValues.r
                        let s = event.returnValues.s
                        let signature = {v: v, r: r, s: s}

                        history.push({
                            timestamp: this.utils.convert_unix_time(event.returnValues.timestamp),
                            signature: signature
                        })
                    }
                    resolve(history)
                }).catch((err) => {
                    reject(err)
                })
            } else {
               reject("Connection to verification server not established. Call establish_connection to setup a connection.")
            }
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

const EDITABLE_DATA_STORAGE_BYTECODE = {
        "linkReferences": {},
        "object": "608060405234801561001057600080fd5b50604051608080610273833981016040818152825160208085015183860151606096870151600080885284880180885286905260ff841687890152978701829052608087018190529451939691959094937f330f922dd712baf413b20ba0142bfffe7148baa67e9ab6c157c322435c7db6f7934293899360019360a08083019493601f198301938390039091019190865af11580156100b3573d6000803e3d6000fd5b505060408051601f198101519481526020810193909352600160a060020a03909316828401525090519081900360600190a15050505061017b806100f86000396000f3006080604052600436106100405763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631285d9958114610045575b600080fd5b34801561005157600080fd5b5061006960043560ff6024351660443560643561006b565b005b7313f4cbc19d59fcef7f0543603adaab7bf11bce5c331461008b57600080fd5b604080516000808252602080830180855288905260ff871683850152606083018690526080830185905292517f330f922dd712baf413b20ba0142bfffe7148baa67e9ab6c157c322435c7db6f7934293899360019360a08084019493601f19830193908390039091019190865af115801561010a573d6000803e3d6000fd5b505060408051601f19810151948152602081019390935273ffffffffffffffffffffffffffffffffffffffff909316828401525090519081900360600190a1505050505600a165627a7a7230582045aa1343875979161779495c3731c7de160a6996b484fd4580e48ffa8e07fed70029",
        "opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x40 MLOAD PUSH1 0x80 DUP1 PUSH2 0x273 DUP4 CODECOPY DUP2 ADD PUSH1 0x40 DUP2 DUP2 MSTORE DUP3 MLOAD PUSH1 0x20 DUP1 DUP6 ADD MLOAD DUP4 DUP7 ADD MLOAD PUSH1 0x60 SWAP7 DUP8 ADD MLOAD PUSH1 0x0 DUP1 DUP9 MSTORE DUP5 DUP9 ADD DUP1 DUP9 MSTORE DUP7 SWAP1 MSTORE PUSH1 0xFF DUP5 AND DUP8 DUP10 ADD MSTORE SWAP8 DUP8 ADD DUP3 SWAP1 MSTORE PUSH1 0x80 DUP8 ADD DUP2 SWAP1 MSTORE SWAP5 MLOAD SWAP4 SWAP7 SWAP2 SWAP6 SWAP1 SWAP5 SWAP4 PUSH32 0x330F922DD712BAF413B20BA0142BFFFE7148BAA67E9AB6C157C322435C7DB6F7 SWAP4 TIMESTAMP SWAP4 DUP10 SWAP4 PUSH1 0x1 SWAP4 PUSH1 0xA0 DUP1 DUP4 ADD SWAP5 SWAP4 PUSH1 0x1F NOT DUP4 ADD SWAP4 DUP4 SWAP1 SUB SWAP1 SWAP2 ADD SWAP2 SWAP1 DUP7 GAS CALL ISZERO DUP1 ISZERO PUSH2 0xB3 JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP PUSH1 0x40 DUP1 MLOAD PUSH1 0x1F NOT DUP2 ADD MLOAD SWAP5 DUP2 MSTORE PUSH1 0x20 DUP2 ADD SWAP4 SWAP1 SWAP4 MSTORE PUSH1 0x1 PUSH1 0xA0 PUSH1 0x2 EXP SUB SWAP1 SWAP4 AND DUP3 DUP5 ADD MSTORE POP SWAP1 MLOAD SWAP1 DUP2 SWAP1 SUB PUSH1 0x60 ADD SWAP1 LOG1 POP POP POP POP PUSH2 0x17B DUP1 PUSH2 0xF8 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN STOP PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH2 0x40 JUMPI PUSH4 0xFFFFFFFF PUSH29 0x100000000000000000000000000000000000000000000000000000000 PUSH1 0x0 CALLDATALOAD DIV AND PUSH4 0x1285D995 DUP2 EQ PUSH2 0x45 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x51 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x69 PUSH1 0x4 CALLDATALOAD PUSH1 0xFF PUSH1 0x24 CALLDATALOAD AND PUSH1 0x44 CALLDATALOAD PUSH1 0x64 CALLDATALOAD PUSH2 0x6B JUMP JUMPDEST STOP JUMPDEST PUSH20 0x13F4CBC19D59FCEF7F0543603ADAAB7BF11BCE5C CALLER EQ PUSH2 0x8B JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x40 DUP1 MLOAD PUSH1 0x0 DUP1 DUP3 MSTORE PUSH1 0x20 DUP1 DUP4 ADD DUP1 DUP6 MSTORE DUP9 SWAP1 MSTORE PUSH1 0xFF DUP8 AND DUP4 DUP6 ADD MSTORE PUSH1 0x60 DUP4 ADD DUP7 SWAP1 MSTORE PUSH1 0x80 DUP4 ADD DUP6 SWAP1 MSTORE SWAP3 MLOAD PUSH32 0x330F922DD712BAF413B20BA0142BFFFE7148BAA67E9AB6C157C322435C7DB6F7 SWAP4 TIMESTAMP SWAP4 DUP10 SWAP4 PUSH1 0x1 SWAP4 PUSH1 0xA0 DUP1 DUP5 ADD SWAP5 SWAP4 PUSH1 0x1F NOT DUP4 ADD SWAP4 SWAP1 DUP4 SWAP1 SUB SWAP1 SWAP2 ADD SWAP2 SWAP1 DUP7 GAS CALL ISZERO DUP1 ISZERO PUSH2 0x10A JUMPI RETURNDATASIZE PUSH1 0x0 DUP1 RETURNDATACOPY RETURNDATASIZE PUSH1 0x0 REVERT JUMPDEST POP POP PUSH1 0x40 DUP1 MLOAD PUSH1 0x1F NOT DUP2 ADD MLOAD SWAP5 DUP2 MSTORE PUSH1 0x20 DUP2 ADD SWAP4 SWAP1 SWAP4 MSTORE PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF SWAP1 SWAP4 AND DUP3 DUP5 ADD MSTORE POP SWAP1 MLOAD SWAP1 DUP2 SWAP1 SUB PUSH1 0x60 ADD SWAP1 LOG1 POP POP POP POP JUMP STOP LOG1 PUSH6 0x627A7A723058 KECCAK256 GASLIMIT 0xaa SGT NUMBER DUP8 MSIZE PUSH26 0x161779495C3731C7DE160A6996B484FD4580E48FFA8E07FED700 0x29 ",
        "sourceMap": "194:505:0:-;;;334:133;8:9:-1;5:2;;;30:1;27;20:12;5:2;334:133:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;434:24;;;;;;;;;;;;;;;;;;;;;;;;;;334:133;434:24;;;;;;;334:133;;;;;;;415:44;;423:3;;334:133;;434:24;;;;;;;334:133;-1:-1:-1;;434:24:0;;;;;;;;;;;;;;;8:9:-1;5:2;;;45:16;42:1;39;24:38;77:16;74:1;67:27;5:2;-1:-1;;434:24:0;;;-1:-1:-1;;434:24:0;;;415:44;;;434:24;415:44;;;;;;-1:-1:-1;;;;;415:44:0;;;;;;;-1:-1:-1;415:44:0;;;;;;;;;;334:133;;;;194:505;;;;;;"
}

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

const SINGLE_SIGN_AGREEMENT_BYTECODE = {
        "linkReferences": {},
        "object": "6080604052348015600f57600080fd5b5060405160608060ef8339810180604052810190808051906020019092919080519060200190929190805190602001909291905050507f5158cb43b8032450a74940e19d2657b5bd3892b998fa5b41560dc6b4f2066b6042848484604051808581526020018460ff1660ff1681526020018360001916600019168152602001826000191660001916815260200194505050505060405180910390a150505060358060ba6000396000f3006080604052600080fd00a165627a7a72305820d4c606502fe3afd292a618dcc96edaa1761cbacf44a1ddae8ade0477c89d79c50029",
        "opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH1 0xF JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x40 MLOAD PUSH1 0x60 DUP1 PUSH1 0xEF DUP4 CODECOPY DUP2 ADD DUP1 PUSH1 0x40 MSTORE DUP2 ADD SWAP1 DUP1 DUP1 MLOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 DUP1 MLOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 DUP1 MLOAD SWAP1 PUSH1 0x20 ADD SWAP1 SWAP3 SWAP2 SWAP1 POP POP POP PUSH32 0x5158CB43B8032450A74940E19D2657B5BD3892B998FA5B41560DC6B4F2066B60 TIMESTAMP DUP5 DUP5 DUP5 PUSH1 0x40 MLOAD DUP1 DUP6 DUP2 MSTORE PUSH1 0x20 ADD DUP5 PUSH1 0xFF AND PUSH1 0xFF AND DUP2 MSTORE PUSH1 0x20 ADD DUP4 PUSH1 0x0 NOT AND PUSH1 0x0 NOT AND DUP2 MSTORE PUSH1 0x20 ADD DUP3 PUSH1 0x0 NOT AND PUSH1 0x0 NOT AND DUP2 MSTORE PUSH1 0x20 ADD SWAP5 POP POP POP POP POP PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 LOG1 POP POP POP PUSH1 0x35 DUP1 PUSH1 0xBA PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN STOP PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x0 DUP1 REVERT STOP LOG1 PUSH6 0x627A7A723058 KECCAK256 0xd4 0xc6 MOD POP 0x2f 0xe3 0xaf 0xd2 SWAP3 0xa6 XOR 0xdc 0xc9 PUSH15 0xDAA1761CBACF44A1DDAE8ADE0477C8 SWAP14 PUSH26 0xC500290000000000000000000000000000000000000000000000 ",
        "sourceMap": "26:225:0:-;;;156:93;8:9:-1;5:2;;;30:1;27;20:12;5:2;156:93:0;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;222:20;229:3;234:1;237;240;222:20;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;156:93;;;26:225;;;;;;"
}

const SINGLE_SIGN_AGREEMENT_ABI = [
        {
                "inputs": [
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
                                "name": "v",
                                "type": "uint8"
                        },
                        {
                                "indexed": false,
                                "name": "r",
                                "type": "bytes32"
                        },
                        {
                                "indexed": false,
                                "name": "s",
                                "type": "bytes32"
                        }
                ],
                "name": "Signed",
                "type": "event"
        }
]

const MULTISIG_AGREEMENT_BYTECODE = {
        "linkReferences": {},
        "object": "608060405234801561001057600080fd5b5060405160608061018783398101604081815282516020808501519483015142855260ff8316918501919091528284018590526060840181905291519093927f5158cb43b8032450a74940e19d2657b5bd3892b998fa5b41560dc6b4f2066b60919081900360800190a150505060fc8061008b6000396000f300608060405260043610603e5763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663b3e376a581146043575b600080fd5b348015604e57600080fd5b50606160ff600435166024356044356063565b005b7313f4cbc19d59fcef7f0543603adaab7bf11bce5c3314608257600080fd5b6040805142815260ff851660208201528082018490526060810183905290517f5158cb43b8032450a74940e19d2657b5bd3892b998fa5b41560dc6b4f2066b609181900360800190a15050505600a165627a7a72305820fb0c8c198569843e74e89503286066c87f50cc0f63033f9778c96616fb5cf5980029",
        "opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x40 MLOAD PUSH1 0x60 DUP1 PUSH2 0x187 DUP4 CODECOPY DUP2 ADD PUSH1 0x40 DUP2 DUP2 MSTORE DUP3 MLOAD PUSH1 0x20 DUP1 DUP6 ADD MLOAD SWAP5 DUP4 ADD MLOAD TIMESTAMP DUP6 MSTORE PUSH1 0xFF DUP4 AND SWAP2 DUP6 ADD SWAP2 SWAP1 SWAP2 MSTORE DUP3 DUP5 ADD DUP6 SWAP1 MSTORE PUSH1 0x60 DUP5 ADD DUP2 SWAP1 MSTORE SWAP2 MLOAD SWAP1 SWAP4 SWAP3 PUSH32 0x5158CB43B8032450A74940E19D2657B5BD3892B998FA5B41560DC6B4F2066B60 SWAP2 SWAP1 DUP2 SWAP1 SUB PUSH1 0x80 ADD SWAP1 LOG1 POP POP POP PUSH1 0xFC DUP1 PUSH2 0x8B PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN STOP PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH1 0x3E JUMPI PUSH4 0xFFFFFFFF PUSH29 0x100000000000000000000000000000000000000000000000000000000 PUSH1 0x0 CALLDATALOAD DIV AND PUSH4 0xB3E376A5 DUP2 EQ PUSH1 0x43 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST CALLVALUE DUP1 ISZERO PUSH1 0x4E JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH1 0x61 PUSH1 0xFF PUSH1 0x4 CALLDATALOAD AND PUSH1 0x24 CALLDATALOAD PUSH1 0x44 CALLDATALOAD PUSH1 0x63 JUMP JUMPDEST STOP JUMPDEST PUSH20 0x13F4CBC19D59FCEF7F0543603ADAAB7BF11BCE5C CALLER EQ PUSH1 0x82 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH1 0x40 DUP1 MLOAD TIMESTAMP DUP2 MSTORE PUSH1 0xFF DUP6 AND PUSH1 0x20 DUP3 ADD MSTORE DUP1 DUP3 ADD DUP5 SWAP1 MSTORE PUSH1 0x60 DUP2 ADD DUP4 SWAP1 MSTORE SWAP1 MLOAD PUSH32 0x5158CB43B8032450A74940E19D2657B5BD3892B998FA5B41560DC6B4F2066B60 SWAP2 DUP2 SWAP1 SUB PUSH1 0x80 ADD SWAP1 LOG1 POP POP POP JUMP STOP LOG1 PUSH6 0x627A7A723058 KECCAK256 CREATE2 0xc DUP13 NOT DUP6 PUSH10 0x843E74E89503286066C8 PUSH32 0x50CC0F63033F9778C96616FB5CF5980029000000000000000000000000000000 ",
        "sourceMap": "28:425:0:-;;;166:95;8:9:-1;5:2;;;30:1;27;20:12;5:2;166:95:0;;;;;;;;;;;;;;;;;;;;;;;;;240:3;233:20;;;;;;;;;;;;;;;;;;166:95;233:20;;;;;;;166:95;;;233:20;;;;;;;;;;166:95;;;28:425;;;;;;"
}

const MULTISIG_AGREEMENT_ABI = [
        {
                "constant": false,
                "inputs": [
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
                "name": "Sign",
                "outputs": [],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
        },
        {
                "inputs": [
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
                                "name": "v",
                                "type": "uint8"
                        },
                        {
                                "indexed": false,
                                "name": "r",
                                "type": "bytes32"
                        },
                        {
                                "indexed": false,
                                "name": "s",
                                "type": "bytes32"
                        }
                ],
                "name": "Signed",
                "type": "event"
        }
]
