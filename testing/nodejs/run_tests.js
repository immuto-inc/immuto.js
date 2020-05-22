let Immuto = require("../../nodejs/immuto.js")
let crypto = require('crypto')
let fs = require('fs')

const IMMUTO_URL = "http://localhost:8000"
let im = Immuto.init(true, IMMUTO_URL)

let email = process.env.EMAIL
let password = process.env.PASSWORD

if (!email) {
   console.error("EMAIL not set")
   process.exit()
}

if (!password) {
   console.error("PASSWORD not set")
   process.exit()
}

run_tests(email, password)

async function run_tests(email, password) {
    try {       
        await im.authenticate(email, password) 
        await test_org_member_registration()
        await im.deauthenticate() // de-authenticate org-member
        await im.authenticate(email, password) // re-authenticate org-admin

        await data_management_tests()
        await test_encryption()


        await test_sharing()

        console.log("All tests passed!")

        // await test_file_upload() NOT SUPPORTED IN BACKEND ATM
        // await digital_agreement_tests() // deprecated, for now
    } catch (err) {
        console.error("Error during tests:")
        console.error(err)
    }
}

async function test_org_member_registration() {
    const newUserEmail = "test@test.com"
    const userPassword = "testpassword"
    
    try {
        const registrationToken = await im.permission_new_user(newUserEmail)
        await im.deauthenticate() // de-authenticate org-admin
        await im.register_user(newUserEmail, userPassword, registrationToken)
        await im.authenticate(newUserEmail, userPassword)
    } catch(err) {
        throw err
    }
}

async function data_management_tests() {
    let content = "EXAMPLE CONTENT"
    let recordName = "A Record"
    let type = "basic" // alternatively, could be 'editable'
    let desc = "Record Description" // optional

    try {
        let recordID = await im.create_data_management(content, recordName, type, password, desc)
        let verified = await im.verify_data_management(recordID, type, content)

        if (!verified) {
            throw new Error("Failed verification of data management")
        }

        console.log('Passed basic data management test')
    } catch(err) {
        throw err
    }

    try {
        let recordID = await im.create_data_management(content, "Editable Record", 'editable', password, desc)
        let verified = await im.verify_data_management(recordID, type, content)

        if (!verified) {
            throw new Error("Failed verification of editable data management")
        }

        let updatedContent = "NEW_CONTENT"
        let update = await im.update_data_management(recordID, updatedContent, password)
        verified = await im.verify_data_management(recordID, type, updatedContent)

        if (!verified) {
            throw new Error(`Failed verification of editable data management after update for recordID ${recordID}`)
        }

        console.log('Passed editable')
    } catch(err) {
        throw err
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
            throw "Failed verification of digital agreement"
        }
    } catch(err) {
        throw err
    }
}

async function test_encryption(attempts) {
    attempts = attempts || 1000

    for (let i=0; i < attempts; i++){
        let plaintext = crypto.randomBytes(attempts < 32 ? 32 : attempts).toString('hex')
        // password = crypto.randomBytes(32).toString('binary')

        let cipherObject = im.encrypt_string(plaintext)
        if (cipherObject.ciphertext == plaintext) {
            throw new Error("encrypt_string did not modify the plaintext at all...")
        }

        let ciphertext = cipherObject.ciphertext
        let key = cipherObject.key
        let iv = cipherObject.iv
        let decrypted = im.decrypt_string(ciphertext, key, iv) 
        if (decrypted !== plaintext) {
            throw new Error(`Failed to decrypt. correct plaintext: ${plaintext} result: ${decrypted}`)
        }

        key = im.generate_key_from_password(password)
        cipherObject = im.encrypt_string_with_key(plaintext, key)
        if (cipherObject.ciphertext == plaintext) {
            throw new Error("encrypt_string did not modify the plaintext at all... (using passgen key)")
        }

        ciphertext = cipherObject.ciphertext
        key = cipherObject.key
        iv = cipherObject.iv
        decrypted = im.decrypt_string(ciphertext, key, iv)
        if (decrypted !== plaintext) {
            throw new Error(`Failed to decrypt [using password]. correct plaintext: ${plaintext} result: ${decrypted}`)
        }

        cipherObject = im.encrypt_string_with_password(plaintext, password)
        if (cipherObject.ciphertext == plaintext) {
            throw new Error("encrypt_string did not modify the plaintext at all... (using convenience passgen key)")
        }

        ciphertext = cipherObject.ciphertext
        key = cipherObject.key
        iv = cipherObject.iv
        if (im.decrypt_string(ciphertext, key, iv) !== plaintext) {
            throw new Error("Failed to decrypt correct plaintext (using convenience passgen key)")
        }
    }
}

async function test_file_upload() {
    try  {
        const fileContent = fs.readFileSync('../testing/nodejs/testfile.txt').toString()
        console.log(fileContent)
        const recordID = await im.upload_file_content(fileContent, "test", password, '')
        console.log(recordID)
        // const downloaded = await im.download_file_for_recordID(recordID, password, 0, true)
        // console.log(downloaded)
    } catch(err) {
        throw err
    }
    
}

async function test_sharing() {
    let content = "EXAMPLE CONTENT"
    let recordName = "A Record"
    let type = "basic" // alternatively, could be 'editable'
    let desc = "Record Description" // optional

    try {
        let recordID = await im.create_data_management(content, recordName, type, password, desc)
        await im.share_record_access(recordID, "test@test.com")
        await im.share_record_access(recordID, "test@test.com") // ensure no duplication
    } catch(err) {
        throw err
    }
}
