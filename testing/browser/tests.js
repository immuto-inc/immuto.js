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

function run_tests() {
       im.authenticate(email, password).then((result) => {
                console.log(result)
        }).catch((err) => {
                console.error(err)
        })
}

