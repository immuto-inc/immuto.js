const IN_BROWSER = true;
const IMMUTO_URL = "http://localhost:8005"
let im = Immuto.init(true, IMMUTO_URL)

let email = IN_BROWSER ? window.localStorage.email : process.env.EMAIL
let password = IN_BROWSER ? window.localStorage.password : process.env.PASSWORD

if (!(email && password)) {
    const errMessage = "Email and password are required"
    if (!IN_BROWSER) {
        console.error(errMessage)
        process.exit()
    } else {
        alert(errMessage)
    }
} else {
    run_tests(email, password)
}

function validate_recordID(recordID) {
    const parsed = im.utils.parse_record_ID(recordID) // throws error on issue
    return recordID
}

function assert_throw(assertion, message) {
    if (!assertion) {
        throw new Error(message)
    }
}

async function run_tests(email, password) {
    try {       
        await im.deauthenticate() // in case auth cached by browser
        await im.authenticate(email, password) 
        
        // await test_org_member_registration()
        // await im.deauthenticate() // de-authenticate org-member
        // await im.authenticate(email, password) // re-authenticate org-admin
 
        await test_bad_usage()
        await data_management_tests()
        await test_encryption()
        if (IN_BROWSER) await test_file_upload()  
        if (IN_BROWSER) await test_sharing()      
        if (IN_BROWSER) await test_example_usage()

        console.log("All tests passed!")
    } catch (err) {
        console.error("Error during tests:")
        console.error(err)
    } finally {
        if (!IN_BROWSER) process.exit()
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

        console.log("Passed member registration test")
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
        const recordID = await im.create_data_management(content, recordName, type, password, desc)
        validate_recordID(recordID)
        let verified = await im.verify_data_management(recordID, type, content)

        if (!verified) {
            throw new Error("Failed verification of digital agreement")
        }
        assert_throw(verified.email === im.email, `Verified email ${verified.email} does not match auth email ${im.email}`)

        console.log("Passed basic data management test")
    } catch(err) {
        throw err
    }

    try {
        const recordID = await im.create_data_management(content, "Editable Record", 'editable', password, desc)
        validate_recordID(recordID)
        let verified = await im.verify_data_management(recordID, type, content)

        if (!verified) {
            throw new Error("Failed verification of editable record")
        }
        assert_throw(verified.email === im.email, `Verified email ${verified.email} does not match auth email ${im.email}`)

        let updatedContent = "NEW_CONTENT"
        let update = await im.update_data_management(recordID, updatedContent, password)
        verified = await im.verify_data_management(recordID, type, updatedContent)

        if (!verified) {
            throw new Error("Failed verification of editable record after update")
        }
        assert_throw(verified.email === im.email, `Verified email ${verified.email} does not match auth email ${im.email}`)

        console.log("Passed editable data management test")
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
        validate_recordID(recordID)
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
        validate_recordID(recordID)
        let data = await im.download_file_data(recordID, password)
        if (fileContent !== data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        verified = await im.verify_data_management(recordID, 'editable', data)
        if (!verified) {
            throw new Error("Failed verification")
        }
        assert_throw(verified.email === im.email, `Verified email ${verified.email} does not match auth email ${im.email}`)

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
        // im.email is now test@test.com and should not match the record
        assert_throw(verified.email !== im.email, `Verified email ${verified.email} should not match auth email ${im.email}`)
        assert_throw(verified.email === "sebastian.a.coates@gmail.com", `Verified email ${verified.email} does not match auth email "sebastian.a.coates@gmail.com"`)

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
        validate_recordID(recordID)
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

async function test_bad_usage() {
    for (const { name, badUsage, expectedError } of BAD_USAGES) {
        try {
            await badUsage() // should throw error
            throw new Error(`Failed to catch bad usage: ${name}`)
        } catch(err) {
            const message = err.message || err // thrown error || promise rejection
            assert_throw(message === expectedError, `'${message}' does not match expected error: '${expectedError}'`)
        }
    }
    console.log("Passed bad usage tests!")
}
const BAD_USAGES = [
    {
        name: "Create no args",
        badUsage: () => {return im.create_data_management()},
        expectedError: "No content given"
    },
    {
        name: "Create no name",
        badUsage: () => {return im.create_data_management("Content")},
        expectedError: "No name given"
    },
    {
        name: "Create no type",
        badUsage: () => {return im.create_data_management("Content", "Name")},
        expectedError: "No type given"
    },
    {
        name: "Create no password",
        badUsage: () => {return im.create_data_management("Content", "Name", 'editable')},
        expectedError: "No password given"
    },
    {
        name: "Create bad type",
        badUsage: () => {return im.create_data_management("Content", "Name", 'bad_type', 'password')},
        expectedError: "Invalid type: bad_type"
    },
    {
        name: "Update no recordID",
        badUsage: () => {return im.update_data_management()},
        expectedError: "No recordID given"
    },
    {
        name: "Update no content",
        badUsage: () => {return im.update_data_management("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000", '')},
        expectedError: "No newContent given"
    },
    {
        name: "Update no password",
        badUsage: () => {return im.update_data_management("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000", 'bad_type', '')},
        expectedError: "No password given"
    },
    {
        name: "Update invalid recordID",
        badUsage: () => {return im.update_data_management("0x6000000", "newContent", "password")},
        expectedError: "Invalid recordID: 0x6000000, reason: length not 48"
    },
    {
        name: "Verify no recordID",
        badUsage: () => {return im.verify_data_management()},
        expectedError: "No recordID given"
    },
    {
        name: "Verify no type",
        badUsage: () => {return im.verify_data_management("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000")},
        expectedError: "No type given"
    },
    {
        name: "Verify no content",
        badUsage: () => {return im.verify_data_management("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000", 'editable')},
        expectedError: "No verificationContent given"
    },
    {
        name: "Verify bad type",
        badUsage: () => {return im.verify_data_management("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000", 'bad_type', 'vContent')},
        expectedError: "Invalid type: bad_type"
    },
    {
        name: "Verify invalid recordID",
        badUsage: () => {return im.get_data_management_history("0x6000000", "editable", "newcontent")},
        expectedError: "Invalid recordID: 0x6000000, reason: length not 48"
    },
    {
        name: "History no recordID",
        badUsage: () => {return im.get_data_management_history()},
        expectedError: "No recordID given"
    },
    {
        name: "History no type",
        badUsage: () => {return im.get_data_management_history("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000")},
        expectedError: "No type given"
    },
    {
        name: "History invalid recordID",
        badUsage: () => {return im.get_data_management_history("0x6000000", "editable")},
        expectedError: "Invalid recordID: 0x6000000, reason: length not 48"
    },
    {
        name: "History bad type",
        badUsage: () => {return im.get_data_management_history("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000", 'bad_type')},
        expectedError: "Invalid type: bad_type"
    },
]