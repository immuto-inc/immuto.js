let email = window.localStorage.email
let password = window.localStorage.password

if (!email) {
   alert("No email set")
}

if (!password) {
    alert("No password set")
}

const IMMUTO_URL = "http://localhost:8005"
let im = Immuto.init(true, IMMUTO_URL)

if (email && password) run_tests(email, password)

async function run_tests(email, password) {
    try {       
        await im.deauthenticate() // in case auth cached by browser
        await im.authenticate(email, password) 
        
        // await test_org_member_registration()
        // await im.deauthenticate() // de-authenticate org-member
        // await im.authenticate(email, password) // re-authenticate org-admin

        await data_management_tests()
        await test_encryption()
        await test_file_upload()
        await test_sharing()
        await test_example_usage() 

        // await digital_agreement_tests() // deprecated, for now

        console.log("All tests passed!")
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
            throw new Error("Failed verification of digital agreement")
        }
        console.log("Passed basic data management test")
    } catch(err) {
        throw err
    }

    try {
        let recordID = await im.create_data_management(content, "Editable Record", 'editable', password, desc)
        let verified = await im.verify_data_management(recordID, type, content)

        if (!verified) {
            throw new Error("Failed verification of editable record")
        }

        let updatedContent = "NEW_CONTENT"
        let update = await im.update_data_management(recordID, updatedContent, password)
        verified = await im.verify_data_management(recordID, type, updatedContent)

        if (!verified) {
            throw new Error("Failed verification of editable record after update")
        }
        console.log("Passed editable data management test")
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
        let plaintext = 'asd8fu1203hfoiasvjnaosdf081083u12iufnojasdnfrandom'

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
    console.log("Passed encryption tests")
}

async function test_file_upload() {
    try  {
        const fileContent = "test file content"
        const recordID = await im.upload_file_data(fileContent, "test", password, '')
        const downloaded = await im.download_file_for_recordID(recordID, password, 0, true)
        if (fileContent !== downloaded.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        console.log("Passed file upload test")
    } catch(err) {
        throw err
    }
}

async function test_sharing() {
    try {
        const fileContent = "test file content"
        const recordID = await im.upload_file_data(fileContent, "test", password)
        let data = await im.download_file_data(recordID, password)
        if (fileContent !== data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        verified = await im.verify_data_management(recordID, 'editable', data)
        if (!verified) {
            throw new Error("Failed verification")
        }

        await im.share_record(recordID, "test@test.com", password)

        await im.deauthenticate()
        await im.authenticate("test@test.com", "testpassword")
        data = await im.download_file_data(recordID, "testpassword")
        if (fileContent !== data) {
            throw new Error("Uploaded content does not match downloaded content for shared recipient")
        }
        verified = await im.verify_data_management(recordID, 'editable', data)
        if (!verified) {
            throw new Error("Failed verification")
        }
        console.log("Passed record sharing test")
    } catch(err) {
        throw err
    }
}

async function test_example_usage() {
    await im.deauthenticate() // in case auth cached by browser

    try {
        const email1 = email
        const pass1 = password
        const email2 = "test@test.com"
        const pass2 = "testpassword"
        await im.authenticate(email1, pass1) // authenticate with user 1

        const fileContent = "example file content"
        const fileName = "Test Name"
        const recordID = await im.upload_file_data(fileContent, fileName, pass1)
        let data = await im.download_file_data(recordID, pass1)
        if (fileContent !== data) {
            throw new Error("Failed to downloaded personal record")
        }

        await im.share_record(recordID, email2, pass1)
        await im.deauthenticate()
        await im.authenticate(email2, pass2) // authenticate with user 2

        data = await im.download_file_data(recordID, pass2)
        if (fileContent !== data) {
            console.log("Failed to download shared record")
        }
        console.log("Passed example usage test")
    } catch(err) {
        console.error(err)
    }
}

