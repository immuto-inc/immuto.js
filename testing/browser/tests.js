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

let im = Immuto.init(true, "http://localhost:8000")

async function run_tests() {
    await im.deauthenticate()// ensure user not logged in to start tests
    
    await establish_connection_tests()
    im.connected = false
    
    await im.authenticate(email, password)
    let testResult = await data_management_tests()
    console.log(testResult)

    im.connected = false // test auto connection before record verification
    testResult = await data_management_tests()
    console.log(testResult)

    testResult = await digital_agreement_tests()
    console.log(testResult)

    im.connected = false // test auto connection before record verification
    testResult = await digital_agreement_tests()
    console.log(testResult)
}

// parallel requests should all be successful, including automatic from attempt connection
function establish_connection_tests() {
    return new Promise((resolve, reject) => {
        im.establish_connection(email).then(() => {
            console.log('Concurrent connection working')
            resolve()
        }).catch((err) => {
            reject(err)
        })
        im.establish_connection(email).then(() => {
            console.log('Concurrent connection working')
            resolve()
        }).catch((err) => {
            reject(err)
        })
        im.establish_connection(email).then(() => {
            console.log('Concurrent connection working')
            resolve()
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