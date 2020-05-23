# immuto.js

#### Immuto's JavaScript library for secure data management

## Documentation
You can find complete documentation <a href="https://www.immuto.io/api-documentation"> here</a>. 

## Example Usage
```
let im = Immuto.init(true, "https://dev.immuto.io") // remove params for production use
try {
    const email1 = "email1@example.com"
    const pass1 = "password1"
    const email2 = "email2@example.com"
    const pass2 = "password2"
    await im.authenticate(email1, pass1) // authenticate with user 1

    const fileContent = "example file content"
    const fileName = "Test Name"
    const recordID = await im.upload_file_data(fileContent, fileName, pass1) // currently browser-only
    let data = await im.download_file_data(recordID, pass1) // currently browser-only
    if (fileContent === data) {
        console.log("Successfully downloaded personal record")
    }

    await im.share_record(recordID, email2, pass1) // email2 must be registered and successfully logged-in once
    await im.deauthenticate()
    await im.authenticate(email2, pass2) // authenticate with user 2

    data = await im.download_file_data(recordID, pass2) // currently browser-only
    if (fileContent === data) {
        console.log("Successfully downloaded shared record")
    }    

    await im.deauthenticate()
} catch(err) {
    console.error(err)
}
```

## Installation

### NodeJS
```
npm install immuto-sdk --save
```
Please ensure you use "immuto-sdk" and not "immuto"

### Browser
You may download a pre-built version by looking at the "Releases" tab on GitHub. Include
in an HTML page as follows:
```
<script src="immuto.js"></script>
```

If you would like to build the browser code from scratch, you will need NPM and a tool like Browserify:
```
git clone https://www.github.com/immuto-inc/immuto.js
cd immuto.js/browser
npm install
browserify immuto_browser.js --s Immuto -o immuto.js
```
