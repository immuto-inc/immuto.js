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
    //await im.deauthenticate()// ensure user not logged in to start tests
    try {
        await im.authenticate(email, password)
    } catch(err) {

    }
    await establish_connection_tests()
    //await data_management_tests()
}

// parallel requests should all be successful, including automatic from attempt connection
async function establish_connection_tests() {
    im.establish_connection(email).then(() => {
        console.log('success')
    }).catch((err) => {
        console.error(err)
    })
    im.establish_connection(email).then(() => {
        console.log('success')
    }).catch((err) => {
        console.error(err)
    })
    im.establish_connection(email).then(() => {
        console.log('success')
    }).catch((err) => {
        console.error(err)
    })
}

async function data_management_tests() {
    return new Promise((resolve, reject) => {
        im.authenticate(email, password).then((result) => {
            console.log(result)
        }).catch((err) => {
            console.error(err)
        })
    })
}