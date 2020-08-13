let Immuto = require("../../nodejs/immuto.js")
let crypto = require('crypto')
let fs = require('fs')

const IN_BROWSER = false;
const IMMUTO_URL = "http://localhost:8005"
let im = Immuto.init(true, IMMUTO_URL)

const email = IN_BROWSER ? window.localStorage.email : process.env.EMAIL
const password = IN_BROWSER ? window.localStorage.password : process.env.PASSWORD
const email2 = IN_BROWSER ? window.localStorage.email2 : process.env.EMAIL2
const password2 = IN_BROWSER ? window.localStorage.password2 : process.env.PASSWORD2


if (!(email && password && email2 && password2)) {
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
        await test_utils()
        await test_bad_usage();
        await im.authenticate(email, password) 
        
        // await test_org_member_registration()
        // await im.deauthenticate() // de-authenticate org-member
        // await im.authenticate(email, password) // re-authenticate org-admin

        await test_password_reset()

        await data_management_tests()
        await test_search()
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

function buffers_are_equal(b1, b2) {
    if (b1.length !== b2.length) return false

    for (let i = 0; i < b1.length; i++) {
        if (b1[i] !== b2[i]) return false
    }

    return true
}

async function test_utils() {
    const testStrings = [
        "test string",
        "a",
    ]
    let buffers = []
    for (let testString of testStrings){
        buffers.push(im.str2ab(testString))
        assert_throw(testString === im.ab2str(im.str2ab(testString)), `testString ${testString} failed to pass ab/str conversion invariant`)
    }
    for (let testBuffer of buffers) {
        assert_throw(buffers_are_equal(testBuffer, im.str2ab(im.ab2str(testBuffer))), `testBuffer ${testBuffer} failed to pass ab/str conversion invariant`)
    }
    
    const testShardIndices = {
        0: "000000",
        1: "000001",
        10: "00000a",
        16777215: "ffffff",
    }
    for (const shardIndex in testShardIndices) {
        const expected = testShardIndices[shardIndex]
        const result = im.utils.shardIndex_to_hex(shardIndex)
        assert_throw(result === expected, `shardIndex_to_hex on ${shardIndex} did not return ${expected}, got ${result}`)

        const original = im.utils.hex_to_shardIndex(result)
        assert_throw(Number(shardIndex) === original, `Failed inverse property of hex_to_shardIndex for ${shardIndex}, got ${original}`)
    
        const inversed = im.utils.shardIndex_to_hex(im.utils.hex_to_shardIndex(expected))
        assert_throw(inversed === expected, `Failed inverse property of shardIndex_to_hex for ${expected}, got ${inversed}`)
    }

    console.log("Passed utils tests")
}

async function test_org_member_registration() {
    const newUserEmail = email2
    const userPassword = password2
    
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
    let recordName = "A Record ?q=5&heloo&&="
    let type = "basic" // alternatively, could be 'editable'
    let desc = "Record Description ?q=5&heloo&&=" // optional
    
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

async function test_search() {    
    const entropy = 32
    let content    = IN_BROWSER ? im.web3.utils.randomHex(entropy) : crypto.randomBytes(entropy)
    let updated    = IN_BROWSER ? im.web3.utils.randomHex(entropy) : crypto.randomBytes(entropy)
    let norecords  = IN_BROWSER ? im.web3.utils.randomHex(entropy) : crypto.randomBytes(entropy)
    let recordName = "Search Record"
    let type = "editable" // alternatively, could be 'editable'
    let desc = "Record Description ?q=5&heloo&&=" // optional
    
    try {
        const recordID = await im.create_data_management(content, recordName, type, password, desc)
        
        let searchResult = await im.search_records_by_content(content)
        assert_throw(searchResult.records && searchResult.records.length, `searchResult: ${searchResult} missing records: ${searchResult.records}`)

        let match = searchResult.records[0]
        assert_throw(match.contractAddr === recordID, `Resulting recordID (as .contractAddr): ${match.contractAddr} does not match expected: ${recordID}`)
        assert_throw(match.recordID === recordID, `Resulting recordID: ${match.recordID} does not match expected: ${recordID}`)


        await im.update_data_management(recordID, updated, password)

        searchResult = await im.search_records_by_content(content)
        assert_throw(searchResult.records && searchResult.records.length, `searchResult: ${searchResult} missing records: ${searchResult.records}`)

        match = searchResult.records[0]
        assert_throw(match.contractAddr === recordID, `Resulting recordID (as .contractAddr): ${match.contractAddr} does not match expected: ${recordID}`)
        assert_throw(match.recordID === recordID, `Resulting recordID: ${match.recordID} does not match expected: ${recordID}`)


        await im.create_data_management(content, recordName, type, password, desc)
        searchResult = await im.search_records_by_content(content)
        assert_throw(searchResult.records.length === 2, `Expecting to find 2 matching records, got ${searchResult.records}`)


        searchResult = await im.search_records_by_content(updated)
        assert_throw(match.contractAddr === recordID, `Resulting recordID (as .contractAddr): ${match.contractAddr} does not match expected: ${recordID}`)
        assert_throw(searchResult.records.length === 1, `Expecting to find 2 matching records, got ${searchResult.records}`)


        searchResult = await im.search_records_by_content(norecords)
        assert_throw(searchResult.records.length === 0, `Expecting to find no matching records, got ${searchResult.records}`)


        console.log("Passed search tests")
    } catch(err) {
        throw err
    }
}

async function test_encryption(attempts) {
    attempts = attempts || 10

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

        await im.share_record(recordID, email2, password)

        await im.deauthenticate()
        await im.authenticate(email2, password2)
        data = await im.download_file_data(recordID, password2)
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
        await im.authenticate(email2, password2) // authenticate with user 2

        data = await im.download_file_data(recordID, password2)
        if (fileContent !== data) {
            console.log("Failed to download shared record")
        }
        console.log("Passed example usage test")
    } catch(err) {
        console.error(err)
    }
}

async function test_password_reset() {
    const resetEmail = email2
    const originalPassword = password2
    const newpassword = "newpassword"

    let personalRecord = ""
    let changedPersonalRecord = ""
    let sharedRecord = ""
    const personalContent = "Personal Record Content"
    const sharedContent = "Shared Record Content"

    await im.authenticate(resetEmail, originalPassword)

    if (IN_BROWSER) {
        personalRecord = await im.upload_file_data(personalContent, "test", originalPassword)

        let personalDownload = await im.download_file_for_recordID(personalRecord, originalPassword, 0, true)
        if (personalContent !== personalDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }

        
        await im.authenticate(email, password)
        sharedRecord = await im.upload_file_data(sharedContent, "shared test", password)
        await im.share_record(sharedRecord, resetEmail, password)

        await im.authenticate(resetEmail, originalPassword)
        let sharedDownload = await im.download_file_for_recordID(sharedRecord, originalPassword, 0, true)
        if (sharedContent !== sharedDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        console.log("Passed decryption before password reset (both personal and shared)")



        await im.reset_password(originalPassword, newpassword)

        changedPersonalRecord = await im.upload_file_data(personalContent, "test", newpassword)
        let changedDownload = await im.download_file_for_recordID(changedPersonalRecord, newpassword, 0, true)
        if (personalContent !== changedDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }

        let rePersonalDownload = await im.download_file_for_recordID(personalRecord, newpassword, 0, true)
        if (personalContent !== rePersonalDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        let reSharedDownload = await im.download_file_for_recordID(sharedRecord, newpassword, 0, true)
        if (sharedContent !== reSharedDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        console.log("Passed decryption after password reset (both personal and shared)")



        await im.reset_password(newpassword, originalPassword) // reset back to original
        let reChangedDownload = await im.download_file_for_recordID(changedPersonalRecord, originalPassword, 0, true)
        if (personalContent !== reChangedDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        let rerePersonalDownload = await im.download_file_for_recordID(personalRecord, originalPassword, 0, true)
        if (personalContent !== rerePersonalDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        let rereSharedDownload = await im.download_file_for_recordID(sharedRecord, originalPassword, 0, true)
        if (sharedContent !== rereSharedDownload.data) {
            throw new Error("Uploaded content does not match downloaded content")
        }
        console.log("Passed decryption after password re-reset (both personal and shared)")
    } else {
        await im.reset_password(originalPassword, newpassword)
        await im.reset_password(newpassword, originalPassword)
    }

    await im.authenticate(email, password) // reset login to original user
    console.log("Passed password reset test")
}

async function test_bad_usage() {
    const BAD_USAGES = [
        {
            name: "Auth no email",
            badUsage: () => {return im.authenticate()},
            expectedError: "Email required for authentication"
        },
        {
            name: "Auth no password",
            badUsage: () => {return im.authenticate(email)},
            expectedError: "Password required for authentication"
        },
        {
            name: "Auth bad password",
            badUsage: () => {return im.authenticate(email, "not the password")},
            expectedError: "Incorrect password"
        },
        {
            name: "Create invalid password",
            badUsage: () => {return im.create_data_management("Content", "Name", 'editable', 'bad_password')},
            expectedError: "Incorrect password"
        },
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
        {
            name: "Upload no content",
            badUsage: () => {return im.upload_file_data()},
            expectedError: "No fileContent given"
        },
        {
            name: "Upload no name",
            badUsage: () => {return im.upload_file_data("content")},
            expectedError: "No fileName given"
        },
        {
            name: "Upload no password",
            badUsage: () => {return im.upload_file_data("content", "name")},
            expectedError: "No password given"
        },
        {
            name: "Upload no password",
            badUsage: () => {return im.upload_file_data("content", "name", "bad_password")},
            expectedError: "Incorrect password"
        },
        {
            name: "Download no recordID",
            badUsage: () => {return im.download_file_data()},
            expectedError: "No recordID given"
        },
        {
            name: "Download no password",
            badUsage: () => {return im.download_file_data("0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000")},
            expectedError: "No password given"
        },
        {
            name: "Download invalid recordID",
            badUsage: () => {return im.download_file_data("0x6000000", "bad_password")},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
            requiresAuth: true,
        },
        {
            name: "Store key no email",
            badUsage: () => {return im.store_user_key_for_record()},
            expectedError: "No userEmail given"
        },
        {
            name: "Store key no recordID",
            badUsage: () => {return im.store_user_key_for_record("sebass@immuto.io")},
            expectedError: "No recordID given"
        },
        {
            name: "Store key no encryptedKey",
            badUsage: () => {return im.store_user_key_for_record("sebass@immuto.io", "0x8DDAAf02468b0b24C2079971BBE56db2C16F509c000000")},
            expectedError: "No encryptedKey given",
            requiresAuth: true,
        },
        {
            name: "Store key bad recordID",
            badUsage: () => {return im.store_user_key_for_record("sebass@immuto.io", "0x6000000", 'encryptedKey')},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
            requiresAuth: true,
        },
        {
            name: "Share record bad recordID",
            badUsage: () => {return im.share_record_access("0x6000000", "sebass@immuto.io")},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
            requiresAuth: true,
        },
        {
            name: "Get record info bad recordID",
            badUsage: () => {return im.get_info_for_recordID("0x6000000")},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
            requiresAuth: true,
        },
        {
            name: "download_file_for_recordID bad recordID",
            badUsage: () => {return im.download_file_for_recordID("0x6000000", "password")},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
            requiresAuth: true,
        },
        {
          name: "utils.parse_record_ID bad recordID",
            badUsage: () => {return im.utils.parse_record_ID("0x6000000")},
            expectedError: "Invalid recordID: 0x6000000, reason: length not 48",
        },
        {
            name: "utils.parse_record_ID no recordID",
            badUsage: () => {return im.utils.parse_record_ID()},
            expectedError: "recordID is required",
        },
        {
            name: "shardIndex_to_hex too big",
            badUsage: () => {return im.utils.shardIndex_to_hex(16777216)},
            expectedError: `shardIndex: 16777216 exceeds width of 6`,
        },
        {
            name: "shardIndex_to_hex negative input",
            badUsage: () => {return im.utils.shardIndex_to_hex(-1)},
            expectedError: `shardIndex must be a positive integer`,
        },
        {
            name: "hex_to_shardIndex no hexString",
            badUsage: () => {return im.utils.hex_to_shardIndex()},
            expectedError: `hexString is required`,
        },
        {
            name: "hex_to_shardIndex invalid type (number)",
            badUsage: () => {return im.utils.hex_to_shardIndex(45)},
            expectedError: `hexString must be a string, got ${typeof 45}`,
        },
        {
            name: "hex_to_shardIndex invalid type (object)",
            badUsage: () => {return im.utils.hex_to_shardIndex({})},
            expectedError: `hexString must be a string, got ${typeof {}}`,
        },
        {
            name: "decrypt_account no password",
            badUsage: () => {return im.decrypt_account()},
            expectedError: `password is required`,
        },
        {
            name: "decrypt_account invalid password",
            badUsage: () => {return im.decrypt_account("invalid password")},
            expectedError: `Incorrect password`,
        },
        {
            name: "get_registration_token no address",
            badUsage: () => {return im.get_registration_token()},
            expectedError: `User's address is required`,
        },
        {
            name: "register_user no email",
            badUsage: () => {return im.register_user()},
            expectedError: `User email is required`,
        },
        {
            name: "register_user no password",
            badUsage: () => {return im.register_user(email)},
            expectedError: `User password is required`,
        },
        {
            name: "permission_new_user no email",
            badUsage: () => {return im.permission_new_user()},
            expectedError: `User email is required`,
        },
        {
            name: "reset_password no oldPassword",
            badUsage: () => {return im.reset_password()},
            expectedError: `oldPassword required`,
        },
        {
            name: "reset_password no newPassword",
            badUsage: () => {return im.reset_password("p1")},
            expectedError: `newPassword required`,
        },
        {
            name: "reset_password passwords match",
            badUsage: () => {return im.reset_password("p1", "p1")},
            expectedError: `oldPassword and newPassword must not match`,
        },
        {
            name: "sign_string no string",
            badUsage: () => {return im.sign_string()},
            expectedError: `string is required for signing`,
        },
        {
            name: "sign_string no password",
            badUsage: () => {return im.sign_string("p1")},
            expectedError: `password is required to sign string`,
        },
        {
            name: "upload_file_for_record no file object",
            badUsage: () => {return im.upload_file_for_record()},
            expectedError: `No file given`,
        },
        {
            name: "upload_file_for_record no content",
            badUsage: () => {return im.upload_file_for_record("p1")},
            expectedError: `No fileContent given`,
        },
        {
            name: "upload_file_for_record no recordID",
            badUsage: () => {return im.upload_file_for_record("p1", "1")},
            expectedError: `No recordID given`,
        },
        {
            name: "upload_file_for_record no password",
            badUsage: () => {return im.upload_file_for_record("p1", "1", "2")},
            expectedError: `No password given`,
        },
        {
            name: "search by hash no hash",
            badUsage: () => {return im.search_records_by_hash()},
            expectedError: `No hash given`,
        },
        {
            name: "search by content no string",
            badUsage: () => {return im.search_records_by_content()},
            expectedError: `No fileContent given`,
        },
        {
            name: "build_full_URL no URL",
            badUsage: () => {return im.build_full_URL()},
            expectedError: `No remoteURL given`,
        },
        {
            name: "decrypt_fileKey_symmetric no keyInfo",
            badUsage: () => {return im.decrypt_fileKey_symmetric()},
            expectedError: `No encryptedKeyInfo given`,
        },
        {
            name: "decrypt_fileKey_symmetric no password",
            badUsage: () => {return im.decrypt_fileKey_symmetric("keyinfo")},
            expectedError: `No password given`,
        },
        {
            name: "decrypt_fileKey_asymmetric no keyInfo",
            badUsage: () => {return im.decrypt_fileKey_asymmetric()},
            expectedError: `No encryptedKeyInfo given`,
        },
        {
            name: "decrypt_fileKey_asymmetric no password",
            badUsage: () => {return im.decrypt_fileKey_asymmetric("keyinfo")},
            expectedError: `No password given`,
        },
        {
            name: "key_to_string no keyInfo",
            badUsage: () => {return im.key_to_string()},
            expectedError: `No keyInfo given`,
        },
        {
            name: "key_to_string iv",
            badUsage: () => {return im.key_to_string({})},
            expectedError: `Given keyInfo has no iv field`,
        },
    ]
    
    for (const { name, badUsage, expectedError, requiresAuth } of BAD_USAGES) {
        try {
            if (requiresAuth) await im.authenticate(email, password)
            await badUsage() // should throw error
            throw new Error(`Failed to catch bad usage: ${name}`)
        } catch(err) {
            const message = err.message || err // thrown error || promise rejection
            if (message.startsWith("Failed to catch bad usage:")) throw err;
            assert_throw(message === expectedError, `'${message}' does not match expected error: '${expectedError}'`)
        }
    }
    console.log("Passed bad usage tests!")
}