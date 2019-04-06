let Immuto = require('../../nodejs/immuto.js')

let im = Immuto.init(true, "http://localhost:8000")

im.authenticate(process.env.EMAIL, process.env.PASSWORD).then((result) => {
        console.log(result)
}).catch((err) => {
        console.error(err)
})
