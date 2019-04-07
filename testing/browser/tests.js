let email = window.localStorage.email
let password = window.localStorage.password

if (!email) {
   email = prompt("Enter test email", ""); 
   window.localStorage.email = email
}

if (!password) {
    password = prompt("Enter test password", "");
    window.localStorage.password = password
}

let currentSession = prompt("Test current session? Leave blank for new session.")

let im = Immuto.init(true, "http://localhost:8000")

async function run_tests() {
    if (!currentSession) {
        await im.deauthenticate()// ensure user not logged in to start tests
    }

    let testResult = await establish_connection_tests()
    im.connected = false
    if (testResult) console.log("Parallel connection attempts successful!");
    
    
    if (!currentSession) {
        await im.authenticate(email, password)
    }
    testResult = await data_management_tests()
    if (testResult) console.log("Data management tests successful!");

    im.connected = false // test auto connection before record verification
    testResult = await data_management_tests()
    if (testResult) console.log("Data management (with auto connect) tests successful!");

    testResult = await digital_agreement_tests()
    if (testResult) console.log("Digital agreement tests successful!");

    im.connected = false // test auto connection before record verification
    testResult = await digital_agreement_tests()
    if (testResult) console.log("Digital agreement (with auto connect) tests successful!");
}

// parallel requests should all be successful, including automatic from attempt connection
function establish_connection_tests() {
    return new Promise((resolve, reject) => {
        let successCount = 0
        im.establish_connection(email).then(() => {
            successCount ++;
            if (successCount == 3) {
                resolve(true)
            }
        }).catch((err) => {
            reject(err)
        })
        im.establish_connection(email).then(() => {
            successCount ++;
            if (successCount == 3) {
                resolve(true)
            }
        }).catch((err) => {
            reject(err)
        })
        im.establish_connection(email).then(() => {
            successCount ++;
            if (successCount == 3) {
                resolve(true)
            }
        }).catch((err) => {
            reject(err)
        })
    })
}

async function data_management_tests() {
    let content = "EXAMPLE CONTENT"
    let recordName = "A Record"
    let type = "basic" // alternatively, could be 'editable'
    let desc = "Record Description" // optional

    try {
        let recordID = await im.create_data_management(content, recordName, type, password, desc)
        let verified = await im.verify_data_management(recordID, type, content)

        if (verified) {
            return true
        } else {
            return false
        }
    } catch(err) {
        return err
    }
}

async function digital_agreement_tests() {
    let content = "EXAMPLE CONTENT"
    let recordName = "A Record"
    let type = "single_sign" // alternatively, could be 'editable'
    let desc = "Record Description" // optional

    try {
        let recordID = await im.create_digital_agreement(content, recordName, type, password, [], desc)
        let verified = await im.verify_digital_agreement(recordID, type, content)

        if (verified) {
            return true
        } else {
            return false
        }
    } catch(err) {
        return err
    }
}